---
title: 'Troubleshooting'
---

weed says why it refuses something, in its log, and at startup on standard error. Start there. This page lists what weed says for the usual problems, and what to do.

Ask weed first:

    # weed check -config /etc/weed/weed.toml       # would weed start with its file?
    # journalctl -u weed -n 50                      # or the end of server.log_file
    # curl -s localhost:9100/status | jq .          # what runs
    $ curl -v --cert ... https://weed.example.org/proc/whoami     # how weed sees a client

## weed does not start {#startup}

| weed says | What to do |
|----|----|
| `unknown option server.prot` | A misspelt or obsolete option. *weed config* lists the options this version knows. |
| `/etc/weed/weed.toml holds secrets but every user can read it (chmod o-r /etc/weed/weed.toml)` | `chmod 600 /etc/weed/weed.toml`. |
| `failed to load the grid-mapfile: open /etc/grid-security/grid-mapfile: no such file or directory` | X.509 needs a grid-mapfile: create it, or set `x509.gridmap`. |
| `weed must run as root, or with the capabilities CAP_SETUID, CAP_SETGID and CAP_KILL (systemd: AmbientCapabilities=)` | Give the account that weed runs as the capabilities, as the RPM's unit does, or run weed as root (see [Installation](installation.html#without-root)). |
| `weed exits: workers no longer start` ... `the starter of workers has exited` | The process that starts weed's workers exited, or was killed: weed exits with it (status 1), and systemd starts both again. The error says how it ended; a signal is someone's kill, or the kernel's OOM killer (see the kernel's log). |
| `cannot confine weed with Landlock: weed confines itself and its workers with Landlock, which this kernel does not have (Landlock ABI 0, and 2 is needed: Linux 5.19 or later, with landlock in lsm=)` | *cat /sys/kernel/security/lsm* lists the security modules: add landlock to the kernel's lsm= boot parameter, or upgrade the kernel (see [Unix accounts](unix-accounts.html#confinement)). weed does not serve unconfined. |
| `cannot confine weed with Landlock: confined with Landlock to write /, weed would reach everything: it does not export /, nor keep its files there` | Export a directory below /, and keep the log, the admin socket and the bans file below / too. |
| `cannot confine weed with Landlock: confined with Landlock, weed could not open /data which it opens without: it is on a file system that Landlock cannot follow ...` | As for workers below: move it. |
| `cannot confine the worker with Landlock: confined with Landlock, workers could not open /data which weed opens without: it is on a file system that Landlock cannot follow` | Landlock refuses every access on some file systems, whatever its rules, such as Docker Desktop's mounts of the host: put the exported directory and weed's binary on another (see [Unix accounts](unix-accounts.html#confinement)). |
| `cannot read the banned users (admin.bans): open /var/lib/weed/bans.json: permission denied` | weed's user must be able to read and write `admin.bans` and its directory. |
| `control plane: /run/weed/admin.sock is in use, by another weed?` | Another weed runs with the same `admin.socket`. Stop it, or give each weed its own. |
| `listen tcp :443: bind: address already in use` | Something else listens on the port: `ss -ltnp 'sport = :443'`. |
| `x509 needs tls`, `oidc needs tokens.issuers, ...` | An option needs another one: set it as weed says. |

With systemd, a failing `weed check` in ExecStartPre stops the start, and *systemctl status weed* shows its message.

## Clients are refused {#refused}

For every refused credential, weed logs "authentication failed" with the method and why, followed by the request's record (see [Logging](logging.html#authentication)). Look the request up by time, client address or user:

    # grep -B1 'status=40[13]' /var/log/weed/weed.log | tail

| Status | weed says | What to do |
|----|----|----|
| 403 | `forbidden: /DC=org/DC=example/OU=Users/CN=Somebody Else is not in the grid-mapfile` | Add the DN to the grid-mapfile, exactly as weed shows it, and reload. |
| 403 | `forbidden: "ghost" is not a usable Unix account: user: unknown user ghost` | Create the account, or map the identity to an existing one. Root is never usable. |
| 403 | `forbidden: no user rule for https://iam.example.org/ matches subject "5f2c1d" and groups ["/atlas"]` | Add a users rule for that group or subject to the issuer (see [Authentication](authentication.html#tokens)). |
| 403 | `forbidden: the token's scopes do not allow this request on /webdav/cms/hosts` | The token needs a storage scope for that path: ask the issuer for it. Mind the issuer's base_path. storage.create does not allow overwriting. |
| 403 | `forbidden: the token has no storage scopes` | The token grants no access: ask for storage.read or storage.modify scopes. |
| 403 | `forbidden: alice is banned (since ...)` | The user is banned: `weed utils bans`. |
| 401 | `no current CRL from "/DC=org/DC=example/CN=Example Grid CA" to check "..." against` | The CA's CRL is missing or expired: run fetch-crl, then reload (see [Reloading](reloading.html#crls)). |
| 401 | `certificate "..." (serial ...) has been revoked` | The certificate is revoked: the user needs a new one. |
| 401 | `certificate verification failed: x509: certificate signed by unknown authority` | Its CA is not in `x509.ca`: install the CA (e.g. the IGTF bundle) and reload. |
| 401 | `token audience ["https://other.example.org"] is not accepted here` | The token is for another service. Add the audience to the issuer's audiences, or have the client ask for a token for weed. |
| 401 | `invalid token: go-jose/go-jose/jwt: validation failed, token is expired (exp)` | The client must get a new token. Check the clocks if tokens seem to expire early. |
| 401 | `token issuer "https://other-iam.example.org/" is not trusted` | Add the issuer to `tokens.issuers` and reload, if its tokens should be accepted. |
| 401 | no "authentication failed" record | The client sent no credentials that an enabled method looks at: e.g. no client certificate (check the client's options, and that \[x509\] is enabled), or a bearer token that is not a JWT while macaroons are disabled. |

Requests refused with 401 are logged with user=nobody, since the credentials named no one weed trusts; those refused with 403 with the user they map to.

## Access to files {#filesystem}

Requests access files as the user's account, so a 403 without an "authentication failed" record comes from the filesystem: the account may not do it. Check as the account:

    # sudo -u alice ls -l /data/alice
    # sudo -u alice touch /data/alice/test

The account needs search permission on every directory above, and write permission on a directory to create or replace files in it. See [Unix accounts](unix-accounts.html#permissions).

A path with a symbolic link in it gets 403, wherever the link is and wherever it points: weed follows none. weed logs it:

    level=WARN msg="refused a name with a symbolic link in it: weed follows none" worker.user=alice worker.pid=1630 path=/alice/data/f request_id=5f0c2a91

Put the directory or file itself in place of the link, or bind-mount the directory there. The local tools of the account follow the link, but weed does not (see [Unix accounts](unix-accounts.html#confinement)).

## 503 Service Unavailable {#unavailable}

| weed says | What to do |
|----|----|
| `no worker for the request ... the 256 workers allowed (unix_users.max_workers) are all busy` | More accounts are active at once than workers are allowed: raise `unix_users.max_workers`. |
| `cannot start a worker ...` | The worker could not start: weed logs why, e.g. a failed cgroup limit, or a binary that changed in place (see [Upgrading](upgrading.html#old-binary)). |
| `cannot start a worker for alice: fork/exec /proc/self/exe: function not implemented` | A seccomp filter refuses clone3, which starts a worker in its cgroup (`unix_users.cgroups`): systemd's RestrictNamespaces=, which refuses it as it cannot look into its arguments, or a container runtime's that predates it. Remove RestrictNamespaces= from weed's unit. |
| `refusing to serve: weed opens files with openat2(2), which this system refuses ...` | A seccomp filter refuses openat2: a container runtime's that predates it, or systemd's RestrictSUIDSGID=, which refuses it as it cannot look into its arguments. Remove RestrictSUIDSGID= from weed's unit, or update the runtime. weed opens every file with openat2, to follow no symbolic link (see [Unix accounts](unix-accounts.html#confinement)). |
| `the exported directory has changed since the worker started (mounted again?): replacing the worker` | A storage was mounted over the exported directory, or in its place: workers, confined with Landlock to the directory as it was when they started, are replaced by workers confined to what is there now (see [Installation](installation.html#mounted)). Nothing to do. |
| `the storage that the exported directory /data was on is no longer mounted ...` | The storage was unmounted, or the one above the exported directory: requests get 503 until it is mounted again, and weed then serves it again within seconds (see [Installation](installation.html#mounted)). weed never serves the directory beneath; to serve it instead, restart weed, without `server.require_mount`. |
| `the exported directory /data is on the file system of /, not on a storage of its own (server.require_mount): is its storage mounted?` | With `server.require_mount`, weed does not start until the storage of the exported directory is mounted. Mount it: systemd starts weed again within a minute. |
| `weed filters its system calls with seccomp on amd64 and arm64, not on ...`, `cannot filter system calls with seccomp` | weed opens only the sockets that Landlock confines (see [Unix accounts](unix-accounts.html#confinement)), with filters of amd64 and arm64, and a kernel with seccomp filters (CONFIG_SECCOMP_FILTER, as every distribution's). |
| `the exported directory has not answered yet, and workers are confined to it with Landlock` | The exported directory did not answer as weed started, and workers start once it does: check its storage (see [below](#hung-storage)). |
| `too many requests in progress for the account (unix_users.max_requests)` | The account's worker has `unix_users.max_requests` requests in progress. If `blocked_threads` in /status stays near `unix_users.max_storage_calls` too, its storage does not answer, or not fast enough (see [below](#hung-storage)); otherwise the account is busy: raise the limit. |
| Too many concurrent third-party copies | `tpc.max_transfers` copies are running; clients retry after the Retry-After. Raise it if the network and disks allow. |
| /healthz: storage unavailable, storage not responding | The exported directory cannot be read, or does not answer within 5 seconds: check the filesystem (a hung NFS or a lost mount, see [below](#hung-storage)). |
| /healthz: storage not mounted | The storage of the exported directory is no longer mounted: see above. |

## Slow transfers {#slow}

weed does not hold transfers back itself. The kernel may: tc on the network interface (see [Limits per account](limits.html#network)), or the account's cgroup limits, such as io.max for its disk, cpu.max and cpu.weight for its CPU, and memory.high, near which the kernel reclaims its memory. The pressure files of its cgroup say how long its workers have waited for each:

    # cat /sys/fs/cgroup/system.slice/weed.service/worker-cms001/io.pressure
    some avg10=41.27 avg60=38.02 avg300=12.55 total=95512644
    full avg10=40.11 avg60=37.20 avg300=12.20 total=93024112
    # tc -s qdisc show dev eth0

Across long distances, the TCP buffers bound each transfer: a connection carries at most one buffer each round trip, 4 MiB by default for what weed sends (see [Performance](performance.html#tcp-buffers)).

## Storage that does not answer {#hung-storage}

When the filesystem of the exported directory stops answering, a hung NFS server or a failing disk, the requests that need it wait in the kernel. Each call to the storage waits with a thread of its worker, which nothing interrupts, not even SIGKILL, until the storage answers, also once its client has given up. A worker makes at most `unix_users.max_storage_calls` (default 256) calls at once (see [Unix accounts](unix-accounts.html#workers)): its other requests wait for one to end, without a thread, and stop waiting when their clients go. Meanwhile:

- The worker's other requests go on, as long as they need nothing from the storage (e.g. files the kernel has cached) and fewer than `unix_users.max_storage_calls` calls are stuck. Once that many are, all the account's requests wait, even for cached files, until a call returns or their clients go. The workers of other accounts, on other storage, go on. weed itself never touches the files, and keeps answering: it looks at the exported directory for Landlock (see [Unix accounts](unix-accounts.html#confinement)) from one goroutine, with what the kernel has cached, and if it does not answer as weed starts, the requests that would start a worker get 503 until it does.
- /healthz answers 503 "storage not responding" after 5 seconds. It looks at the directory once at a time, however often it is called.
- /status shows each worker's stuck threads as `blocked_threads`, also once their clients have gone and `requests` has dropped to 0; `weed_worker_blocked_threads` counts them all. Under load, threads are in that state for moments: alert on a count that stays.
- Stuck requests count towards `unix_users.max_requests` until they end: once they reach it, the account gets 503. Its worker has no more stuck threads than `unix_users.max_storage_calls`.
- An idle worker with stuck threads keeps running, rather than being replaced by a new worker, which could get stuck too. weed logs it once:

      level=WARN msg="an idle worker keeps running: threads of its requests wait in the kernel, for storage that does not answer?" worker.user=alice worker.pid=1630 blocked_threads=40

- A killed worker, by a ban or as weed stops, exits only once its threads return. Reads waiting for data end when killed; writes waiting for the disk (the fsync that ends an upload) do not. weed waits 10 seconds for the worker, then says so and goes on:

      level=ERROR msg="stopping without waiting for the workers that do not exit" error="the worker of alice (pid 1630) has not exited 10s after being killed: 2 of its threads wait in the kernel, for storage that does not answer? A worker exits once they return"

To see where the threads of a worker wait:

    # ps -L -o tid,stat,wchan:32,args -p 1630 | awk 'NR == 1 || $2 ~ /D/'
        TID STAT WCHAN                            COMMAND
       1642 Dl   folio_wait_bit_common            weed worker alice
       1651 Dl   folio_wait_bit_common            weed worker alice
    # cat /proc/1630/task/1651/stack
    [<0>] folio_wait_bit_common+0x174/0x3d8
    [<0>] folio_wait_bit+0x20/0x40
    [<0>] folio_wait_writeback+0x60/0x170
    [<0>] __filemap_fdatawait_range+0x8c/0xf0
    [<0>] file_write_and_wait_range+0xa4/0xd0
    [<0>] ext4_sync_file+0x94/0x4e0
    [<0>] do_fsync+0x54/0xe0
    ...

Then find out why the storage does not answer: the kernel log says it, e.g. "nfs: server ... not responding, still trying", or I/O errors of a disk (`dmesg`, `journalctl -k`). Once the storage answers, the threads return, their requests end, and the workers exit or go idle. Restarting weed does not end them: the stuck workers stay until the storage answers, and the new weed's workers get stuck as well.

## Third-party copies fail {#tpc}

The COPY answer ends with "failure: \<reason\>", and weed logs "third-party copy failed" with the same reason. The usual ones:

- A TLS error with the remote endpoint: its CA is not trusted. Set `tpc.ca_path` to /etc/grid-security/certificates.
- The remote endpoint's address is refused (loopback, private): see [Remote endpoints](tpc.html#remote-endpoints). Storage on a private network needs `tpc.allow_private`.
- The remote answers 401 or 403: the credential in TransferHeaderAuthorization is not valid there, or does not allow the path.
- "client/server checksum mismatch": the data received differs from the checksum that the client gave. Nothing was stored.
- The copy stalled for `tpc.stall_timeout`: the remote stopped sending.

## More detail {#debug}

Set `server.log_level = "debug"` and restart, to log how each request was authenticated and which methods were tried. /proc/whoami and /proc/x509 show what weed makes of a client's credentials.
