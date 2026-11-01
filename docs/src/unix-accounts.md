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

A worker serves at most `unix_users.max_requests` (default 4000) requests at once. It counts each until it has finished it, also once its client has gone, and answers its account's requests beyond with 503 and Retry-After. A request whose storage does not answer stays in progress until the storage does, with one of the worker's threads: the limit keeps such threads from piling up until the worker cannot make more, and dies.

Before it serves, weed starts a worker as nobody, to find problems before the first request. Each worker checks that all its threads run as its account, without capabilities and with no_new_privs, and refuses to serve otherwise. Workers get none of weed's environment, and ignore SIGHUP, which is for weed.

Workers log through weed: their records carry worker.user and worker.pid, and the request_id of the request they serve (see [Logging](logging.html)). They report their metrics to weed, which serves them. `tpc.max_transfers` bounds the third-party copies of all accounts together.

## Workers run weed's build {#same-build}

Workers are started from /proc/self/exe: the binary that weed itself runs, even after an upgrade has replaced it on disk. A new version only runs once weed restarts, for weed and its workers alike. Each worker also reports its Go build ID, and weed refuses workers whose build is not its own, which happens if the binary is overwritten in place. See [Upgrading](upgrading.html).

## What workers reach {#confinement}

Beyond the permissions of its account, two things keep a worker to the exported directory.

Symbolic links
:   Workers open every name beneath the exported directory, and follow a link only when it is relative and stays inside. A link that leads outside, and every absolute link (even one to a file inside), gets 403, is left out of listings, and is logged as *refused a name that leads outside the exported directory*. Otherwise, a user who can make links there, over ssh or NFS, could have weed read whatever the account can, such as /etc.

Landlock
:   With `unix_users.landlock` (the default) and Linux 5.19 or later, with landlock among the security modules (lsm=), weed confines each worker with Landlock as it starts it. Whatever a bug in the worker tries, it may write beneath the exported directory alone, and read only beneath it and /etc, /usr, /lib, /proc and /sys/fs/cgroup (and `tpc.ca_path`, SSL_CERT_FILE and SSL_CERT_DIR), whatever the permissions. It may execute weed alone (and, for a build with cgo, its dynamic loader, which can run other programs, confined the same); it cannot make symbolic links, devices, sockets or FIFOs; from Linux 6.12, nor signal processes or connect to abstract Unix sockets outside its confinement. Each worker checks that it is confined, and refuses to serve otherwise. Landlock does not cover stat, chmod, chown, utime and extended attributes: on files outside the exported directory, permissions alone keep those.

weed logs the rules as it starts, or warns that the kernel has no Landlock, and workers are then confined by permissions only:

    INFO workers are confined with Landlock landlock_abi=6 rules="[write /data read /etc read /proc read /sys/fs/cgroup read /usr read /lib read /lib64 execute /proc/self/exe write /dev/null]"

The rules name the exported directory as it was when the worker started. weed looks at it every 5 seconds, and replaces the workers that started before it changed, such as when a storage is mounted again over it.

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

With `unix_users.cgroups`, the workers of each account run in a cgroup of their own, below weed's. weed's cgroup must be delegated to it (cgroup v2; with systemd, `Delegate=yes` in the unit). weed then moves itself into \<its cgroup\>/main, and starts the workers of alice in \<its cgroup\>/worker-alice, with the cpu, io, memory and pids controllers when they are available. systemd-cgtop and systemd-cgls show what each account uses:

    # systemd-cgls -u weed.service
    Unit weed.service (/system.slice/weed.service):
    ├─main
    │ └─812 weed -config /etc/weed/weed.toml
    ├─worker-alice
    │ └─1630 weed worker alice
    └─worker-cms001
      └─1702 weed worker cms001

`unix_users.cgroup_limits` writes limits into the cgroup of every account (and implies cgroups), unless the limits file sets others for the account (see [Limits per account](limits.html)):

    [unix_users]
    cgroup_limits = ["memory.max=8G", "pids.max=5000", "cpu.weight=100"]

pids.max counts the worker's threads, and a worker that cannot make a thread dies, with all its requests. Each request waiting for its files has a thread, so keep pids.max above `unix_users.max_requests`, with room for the few tens that Go uses besides.

weed checks that each limit has the form file=value when it reads the configuration; the kernel checks the values when weed writes them, when a worker of the account starts and when weed reloads. *weed check* does not set cgroups up, since that would move the process it runs in, so it does not try the values.

## Performance

Downloads relayed from workers run at about 92% of the speed of serving files directly, and uploads at the same speed (1 GiB files over loopback without TLS: about 5200 MB/s against 5600 MB/s). That needs 1 MiB socket buffers, which root gets. If weed runs as another account, also raise net.core.wmem_max and net.core.rmem_max to 1048576, or downloads lose a third:

    # sysctl -w net.core.wmem_max=1048576 net.core.rmem_max=1048576
