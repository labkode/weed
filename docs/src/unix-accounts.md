---
title: 'Unix accounts'
---

Every request accesses files as the Unix account that its credentials map to. weed itself never opens the exported files: it hands each request to the *worker process* of its account, which runs as that account.

## Accounts

The username of every identity must be a local account: the grid-mapfile's for certificates, the issuer's users rule (or the sub claim) for tokens, the user who asked for a macaroon, the htpasswd entry for passwords. Anonymous requests are the account nobody's. weed looks accounts up in the system's user database, which reaches LDAP or SSSD when weed is built with cgo (see [Installation](installation.html#building)).

An identity without an account, or whose account is root, gets 403:

    level=INFO msg="authentication failed" method=x509 error="forbidden: \"ghost\" is not a usable Unix account: user: unknown user ghost" request_id=94479c43
    level=INFO msg=request method=GET path=/webdav/alice/ proto=HTTP/1.1 status=403 bytes=10 duration=1.819958ms user=ghost remote=192.0.2.7:52446 user_agent=curl/7.76.1 request_id=94479c43

weed looks an account up again after a minute, and on reload. When an account's groups change, its next request goes to a new worker, and the old one finishes its requests first.

## Worker processes {#workers}

A worker runs as its account: its UID, GID and supplementary groups, with no capabilities and no_new_privs set, so it cannot gain privileges. The kernel checks permissions and ACLs as for the user, new files and directories belong to the user, and third-party copies read and write the local file as the user. Token scopes and macaroon caveats are checked by weed before the request is handed on.

    $ ps -o user,pid,ppid,args -C weed
    USER         PID    PPID COMMAND
    root         812       1 weed -config /etc/weed/weed.toml
    alice       1630     812 weed worker alice
    cms001      1702     812 weed worker cms001

A worker starts with the first request of its account, and stops after `unix_users.idle_timeout` (default 10m) without one, unless threads of its requests still wait for its storage (see [Troubleshooting](troubleshooting.html#hung-storage)). A worker that dies is replaced at the next request. /status lists the workers, with their pids and how many requests each is serving (see [Monitoring](monitoring.html#status)).

At most `unix_users.max_workers` (default 256) workers take requests. When they are all busy, weed stops the idlest one to make room; when none is idle, requests of other accounts get 503, with Retry-After. Raise the limit if your site has more active accounts than that.

A worker serves at most `unix_users.max_requests` (default 4000) requests at once. It counts each until it has finished it, also once its client has gone, and answers its account's requests beyond with 503 and Retry-After.

Of those, at most `unix_users.max_storage_calls` (default 256) call the storage at once: an open, a stat, a batch of a listing, one read or write of a transfer, the fsync and rename that end an upload. Each call holds one of the worker's threads until the storage answers. Other requests wait for a call to end, without a thread, and stop waiting when their client goes. So a worker has no more threads than that, plus one per CPU and the few tens that Go uses besides, however many requests it serves and however slow its storage is. Without the bound, a worker serving thousands of requests ends up with a thread for each, and one whose storage does not answer piles them up until it cannot make more, and dies. Raise it for storage that serves many calls at once, such as NFS or a parallel filesystem, when the worker's threads in /status (`blocked_threads`) often reach it while the storage keeps up. [Performance](performance.html) says when to change these limits, and what else limits how much weed serves.

Before it serves, weed starts a worker as nobody, to find problems before the first request. Each worker checks that all its threads run as its account, without capabilities and with no_new_privs, and refuses to serve otherwise. Workers get none of weed's environment, and ignore SIGHUP, which is for weed.

Workers log through weed: their records carry worker.user and worker.pid, and the request_id of the request they serve (see [Logging](logging.html)). They report their metrics to weed, which serves them. `tpc.max_transfers` bounds the third-party copies of all accounts together.

## Workers run weed's build {#same-build}

Workers are started from /proc/self/exe: the binary that weed itself runs, even after an upgrade has replaced it on disk. A new version only runs once weed restarts, for weed and its workers alike. Each worker also reports its Go build ID, and weed refuses workers whose build is not its own, which happens if the binary is overwritten in place. See [Upgrading](upgrading.html).

## What workers reach {#confinement}

Beyond the permissions of its account, three things confine a worker.

Symbolic links
:   Workers open every name beneath the exported directory with openat2(2), and follow no symbolic link, wherever it is in the name and wherever it points. A name with a link in it gets 403 and is logged as *refused a name with a symbolic link in it*, and links are left out of listings. Otherwise, a user who can make links there, over ssh or NFS, could have weed read whatever the account can, such as /etc; and a link in a directory would take a token or macaroon for that directory wherever it points. To serve a directory from elsewhere, bind-mount it: a mount point is not a link. openat2 came with Linux 5.6; a worker refuses to serve if a seccomp filter, such as a container's, refuses it.

Landlock
:   weed confines itself and each worker with Landlock as it starts it, and does not start without it: it needs Linux 5.19 or later, with landlock among the security modules (lsm=). Whatever a bug in a worker tries, it may write beneath the exported directory alone, and read only beneath it and /etc, /usr, /lib, /proc and /sys/fs/cgroup (and `tpc.ca_path`, SSL_CERT_FILE and SSL_CERT_DIR), whatever the permissions. It may execute weed alone (and, for a build with cgo, its dynamic loader, which can run other programs, confined the same); it cannot make symbolic links, devices, sockets or FIFOs. From Linux 6.7, it binds no TCP port, and connects to none unless `tpc.enabled`, for third-party copies (Landlock does not confine UDP, nor MPTCP: see seccomp below). From Linux 6.12, it signals no process (but on RHEL 9's kernels, which lack that) and connects to no abstract Unix socket outside its confinement. Each worker checks that it is confined, and refuses to serve otherwise. Landlock does not cover stat, chmod, chown, utime and extended attributes: on files outside the exported directory, permissions alone keep those.

seccomp
:   Landlock's rules of TCP cover TCP alone: not MPTCP, which Go listens with where the kernel has it, and which falls back to TCP with peers that do not have it, nor SCTP, SMC, raw or packet sockets. weed filters the system calls of each worker with seccomp: it opens Unix sockets alone, and with `tpc.enabled` TCP and UDP ones too, UDP to resolve names. It has no io_uring, which opens sockets without socket(2). Each worker checks that it is filtered, and refuses to serve otherwise. The filters are of amd64 and arm64: elsewhere, weed does not start.

weed logs the rules as it starts:

    INFO workers are confined with Landlock landlock_abi=6 rules="[write /data read /etc read /proc read /sys/fs/cgroup read /usr read /lib read /lib64 execute /proc/self/exe write /dev/null]" tcp="no bind, connect (tpc.enabled)" sockets="Unix, netlink, TCP and UDP"

### weed's own process {#process}

weed runs as three kinds of process. weed itself terminates TLS, authenticates requests and relays them; the starter of workers starts the workers, as their accounts; each worker accesses the files of one account:

    # systemd-cgls -u weed.service
    Unit weed.service (/system.slice/weed.service):
    ├─main
    │ ├─812 /usr/bin/weed -config /etc/weed/weed.toml  as weed: no capabilities
    │ └─815 weed starter -config /etc/weed/weed.toml   as weed: CAP_SETUID CAP_SETGID CAP_KILL
    ├─worker-alice
    │ └─1630 weed worker alice                         as alice: no capabilities
    └─worker-cms001
      └─1702 weed worker cms001                        as cms001: no capabilities

weed has no privileges: as it starts, before it reads a request, it starts the starter, then gives up its capabilities (but CAP_NET_BIND_SERVICE, to listen on a port below 1024), and confines itself with Landlock and seccomp. It may write the directories of `server.log_file`, `admin.socket` and `admin.bans`, and read only those, the system's files (as workers) and the files that its configuration names; not the exported directory, which workers alone reach. From Linux 6.7, it binds only its ports, and connects only to token issuers and for third-party copies. With seccomp, it opens Unix, netlink, TCP and UDP sockets alone, and has no io_uring. It is the same as root: a root without capabilities owns root's files, but reaches only what Landlock lets it.

Landlock, seccomp and the capabilities of a process are those of a thread, and what it executes: weed executes itself again, from a thread that it confines, and refuses to start if it then is not confined, or has capabilities. It logs the rules as it does:

    INFO weed confines itself with Landlock, and executes itself again confined, without privileges landlock_abi=6 rules="[read /etc read /proc ... write and make sockets in /run/weed write /var/lib/weed]" tcp="bind 443 9100, connect (token issuers, tpc.enabled)" sockets="Unix, netlink, TCP and UDP" capabilities=CAP_NET_BIND_SERVICE

Confined to /, weed would reach everything: it does not keep its files there.

### The starter of workers {#starter}

The starter keeps the capabilities that starting workers needs, CAP_SETUID and CAP_SETGID, and CAP_KILL to stop them, and nothing else: it reads no request, and does nothing but start the workers that weed asks for, and kill them. weed sends it the name of an account and the two sockets of the worker; the starter looks the account up itself, and starts no worker as root, nor as an account that it finds other than weed does (its uid, gid and groups): an account changed since weed looked it up gets 503 until *systemctl reload weed* looks it up again. It may gain no privileges (no_new_privs), and seccomp lets it open only the sockets of its workers. weed cannot look into it: it is not dumpable, and has capabilities that weed has not.

With CAP_SETUID, the starter can become any account, root too, so it is as trusted as root: it is small, and takes nothing but weed's messages, which it checks. It is not confined with Landlock, so that it follows the exported directory as storage comes and goes (below). Its log is weed's, with `process=starter`. If it exits, weed exits too (status 1), as it can start no worker; systemd starts both again.

### Storage mounted later {#mounted}

Landlock confines to plain directories and to mount points alike. A rule names the directory that its path leads to as the worker starts: with a storage mounted at /data, the root of that storage; without one, the directory /data itself. It covers everything beneath, storage mounted below it later included. It does not cover what is mounted over it, or above it, later, nor what replaces it: a storage mounted at /data after a worker started, or the directory beneath once the storage is unmounted, is out of the worker's reach. The starter looks at the directory every 5 seconds. When a storage is there in its place, the workers confined to the directory as it was finish their requests and stop, and the next requests get workers confined to the storage: weed goes on serving. When the storage that the directory was on, at startup or mounted since, is no longer mounted, no worker starts, and requests get 503 until the storage is back: weed started again would serve the directory beneath (see [Installation](installation.html#mounted)).

Two more would confine workers further, and are not part of weed. A mount namespace per worker, holding only the exported directory and the system files a worker needs (pivot_root, as containers do), would hide what is outside even from stat; weed would need CAP_SYS_ADMIN, and storage mounted after a worker started (autofs, NFS remounts) to propagate into it. systemd's sandboxing confines weed and its workers together, so also the process that terminates TLS and authenticates requests (see [Installation](installation.html#sandboxing)); it does not separate the accounts from each other.

## Permissions

Operations that the filesystem refuses get 403. As with local tools:

- Accounts need search permission on the exported directory and its parents.
- Replacing a file needs write permission on the file as well as on its directory, and the new version belongs to the user who wrote it. (weed writes uploads to a new file, which it renames over the old one: see [Storage](storage.html).)
- Locking an existing file needs write permission on it, so that a user cannot lock others out of their files.
- WebDAV locks are kept by each worker: they only hold against requests of the same account, and are lost when its worker stops.

Plan the layout of the exported directory as you would for local users: a directory per account or per group, with group permissions or ACLs where accounts share data. For example, a directory that the production and user accounts of an experiment both read, and only production writes:

    # mkdir /data/cms
    # chown cmsprod:cms /data/cms
    # chmod 2755 /data/cms        # the group reads; what is created inside stays in group cms

New files and directories get the permissions that weed's umask leaves (0644 and 0755 with systemd's default of 0022).

## cgroups

With `unix_users.cgroups`, the workers of each account run in a cgroup of their own, below weed's. weed's cgroup must be delegated to it (cgroup v2; with systemd, `Delegate=yes` in the unit). The starter of workers then moves itself and weed into \<its cgroup\>/main, and starts the workers of alice in \<its cgroup\>/worker-alice, with the cpu, io, memory and pids controllers when they are available. systemd-cgtop and systemd-cgls show what each account uses (see [above](#process)).

`unix_users.cgroup_limits` writes limits into the cgroup of every account (and implies cgroups), unless the limits file sets others for the account (see [Limits per account](limits.html)):

    [unix_users]
    cgroup_limits = ["memory.max=8G", "pids.max=5000", "cpu.weight=100"]

pids.max counts the worker's threads, and a worker that cannot make a thread dies, with all its requests. Each call to the storage holds a thread, so keep pids.max above `unix_users.max_storage_calls`, with room for a thread per CPU and the few tens that Go uses besides.

weed checks that each limit has the form file=value when it reads the configuration; the kernel checks the values when weed writes them, when a worker of the account starts and when weed reloads. *weed check* does not set cgroups up, since that would move the process it runs in, so it does not try the values.
