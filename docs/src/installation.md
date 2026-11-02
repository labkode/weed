---
title: 'Installation'
---

weed is a single binary, without runtime dependencies. You build it from source with Go, install it, and run it as a systemd service, or under another supervisor (see [Without systemd](#without-systemd)).

## Building

weed needs Go 1.26 or later to build. In a checkout of the source:

    $ git clone https://github.com/labkode/weed.git
    $ cd weed
    $ make build
    $ ./weed version
    weed v1.2.0
    commit   46a37813bc81d7a1b9a8b1e2a9e1f3c3e6c2a0d4 (2026-10-28T16:07:11Z)
    go       go1.27.3 linux/amd64
    build    go:2CX-x4_-THjPR2Dy4JCE/TtMef8lUxfkIJsGhiXwh/3-NbDYhNvYZpdojQpjfp/Dg3...

Built from a git checkout, the binary records its version and commit, which weed reports when it runs (see [What runs](what-runs.html)). Build where you can see the version: a tree with uncommitted changes gives a version ending in +dirty.

How weed finds accounts depends on how it is built. With cgo (the default when a C compiler is installed), it asks the system's user database, so accounts in LDAP or SSSD work as configured in /etc/nsswitch.conf. Without cgo (`CGO_ENABLED=0`), it reads /etc/passwd and /etc/group only. Build with cgo if your users are not all in /etc/passwd.

## Installing

    # install -m 0755 weed /usr/local/bin/weed

Keep the binary readable and executable by everyone (0755): the workers that run as the users are started from it.

weed reads and writes these, which [Files](files.html) lists in full:

| Path | What |
|----|----|
| /etc/weed/weed.toml | the configuration file; mode 0600 if it holds secrets, which weed requires |
| /etc/weed/issuers.json | the token issuers, if you accept tokens |
| /etc/grid-security/ | the host certificate and key, the CA certificates and CRLs, the grid-mapfile |
| /run/weed/admin.sock | the control plane's socket, which weed creates (see [Banning users](banning.html)) |
| /var/lib/weed/bans.json | the banned users, written by weed at the first ban |

Create /etc/weed. weed creates /run/weed and /var/lib/weed when it needs them.

    # mkdir -m 0755 /etc/weed

## The systemd service {#systemd}

weed is a notify service: it tells systemd when it is ready (once it listens), when it reloads and when it stops, and keeps its status line current. Write /etc/systemd/system/weed.service:

    [Unit]
    Description=weed WebDAV server
    After=network-online.target remote-fs.target
    Wants=network-online.target
    # Restart= for ever, not 5 times in 10 seconds and then never again
    StartLimitIntervalSec=0

    [Service]
    # systemd 253 or later; before, Type=notify and ExecReload=/bin/kill -HUP $MAINPID
    Type=notify-reload
    ExecStartPre=/usr/local/bin/weed check -config /etc/weed/weed.toml
    ExecStart=/usr/local/bin/weed -config /etc/weed/weed.toml
    # After a crash, and when weed exits to start again (status 75): in 2 seconds, and
    # up to a minute apart while it keeps failing (RestartSteps=: systemd 254)
    Restart=on-failure
    RestartSec=2s
    RestartSteps=5
    RestartMaxDelaySec=1min
    # A worker that the kernel kills for its memory does not stop weed
    OOMPolicy=continue

    [Install]
    WantedBy=multi-user.target

*weed check* reads the configuration and every file it names before weed starts, so that *systemctl start* fails with the reason weed would not start. A restart stops weed before ExecStartPre runs, so run *weed check* yourself before restarting (see [Upgrading](upgrading.html)). With Type=notify-reload, *systemctl reload weed* re-reads the credentials (see [Reloading](reloading.html)) and returns once that is done.

    # systemctl daemon-reload
    # systemctl enable --now weed
    # systemctl status weed
    ...
         Status: "Serving since 2026-10-28 16:07:11 UTC: weed v1.2.0, /etc/weed/weed.toml
                  (sha256 b78bbdeed036)"
    ...

If weed cannot start, the journal says why, also when weed logs to a file (`server.log_file`):

    weed: cannot start: failed to load the grid-mapfile: open /etc/grid-security/grid-mapfile: no such file or directory

On stop, weed stops taking connections, and gives the requests in progress 30 seconds to finish (so do the workers). Transfers still running after that are cancelled; an upload that is cancelled never replaces a file.

weed starts again on its own: after a crash, and after it exited because a storage was mounted over the exported directory (below). While it keeps failing to start, such as while its storage is not mounted (`require_mount`, below), systemd tries again ever less often, every minute at last, and never gives up. With OOMPolicy=continue, a worker that the kernel kills for its memory is one that weed starts again at the account's next request, and the other accounts do not notice; without it, systemd would stop weed as a whole (its default, except with Delegate=yes). Limit the memory of each account (`memory.max` in `unix_users.cgroup_limits`, see [Limits per account](limits.html)): an account that reaches it has its worker killed within its own cgroup, never weed's own process.

Add `Delegate=yes` to \[Service\] if you run each worker in a cgroup of its own (`unix_users.cgroups`, see [Unix accounts](unix-accounts.html#cgroups)).

### Sandboxing {#sandboxing}

systemd can confine weed and its workers together, beyond what weed does for workers (see [Unix accounts](unix-accounts.html#confinement)), so also the process that terminates TLS and authenticates requests, as root. For instance, in \[Service\]:

    # All read-only, but /dev, /proc, /sys, and RuntimeDirectory= and StateDirectory=
    ProtectSystem=strict
    # /run/weed for admin.socket, /var/lib/weed for admin.bans
    RuntimeDirectory=weed
    StateDirectory=weed
    # The exported directory, and that of server.log_file
    ReadWritePaths=/data
    # Unless the exported directory is below /home
    ProtectHome=yes
    PrivateTmp=yes

weed confines itself with Landlock as well (see [Unix accounts](unix-accounts.html#process)). ReadWritePaths= makes writable what /data is as weed starts, as Landlock does: weed starts again when it changes (below).

### A storage mounted at the exported directory {#mounted}

weed is confined to the exported directory as it was when weed started (see [Unix accounts](unix-accounts.html#process)), and looks at it every 5 seconds:

- When the storage that the directory was on is no longer mounted, so that the directory is on the file system of / again, or gone (a storage mounted above it), weed blocks. Requests get 503, /healthz too, and weed never serves the directory beneath: uploads there would fill the root file system, and be hidden once the storage is back. weed goes on running: `systemctl status weed` says since when it is blocked, /status has `storage_unmounted`, and the metric `weed_storage_unmounted` is 1 (see [Metrics](metrics.html)).
- When a storage is mounted over the directory or in its place, a remount, the storage mounted again after it was lost, or one mounted after weed started, weed lets the requests in progress finish (30 seconds at most), and exits with status 75. systemd starts it again (Restart=on-failure), confined to what is there then; meanwhile, requests get 503.

A storage that comes back thus needs no one: weed serves it again within seconds.

    level=ERROR msg="the storage of the exported directory is no longer mounted: workers do not start, until it is again" error="the storage that the exported directory /data was on when weed started is no longer mounted: ..."
    level=WARN msg="weed exits, to be started again by its supervisor, confined to the exported directory as it now is" status=75 error="weed may no longer open the exported directory /data, a storage mounted over it or in its place since weed started: ..."

weed knows that there was a storage only while it runs. One that starts while the storage is not mounted, after a boot where the mount failed, a crash, or `systemctl restart`, serves the directory beneath. If the exported directory is on a storage of its own, mounted at it or above it (NFS, a file system of its own), set `require_mount`, which refuses to serve it from the file system of /:

    [server]
    dir = "/data"
    require_mount = true

weed then does not start while the storage is not mounted, and starts once it is back, as systemd tries again. After=remote-fs.target starts weed after the network file systems at boot; RequiresMountsFor=/data is not needed, and would do more: a mount that fails at boot would fail weed's start, which Restart= does not retry.

### Socket activation {#socket-activation}

With a socket unit, systemd listens on weed's ports and passes the sockets to weed: while weed restarts, after a crash, a remount or an upgrade, clients wait in the queue instead of being refused, and weed binds no port (as an account of its own, it needs no CAP_NET_BIND_SERVICE). Write /etc/systemd/system/weed.socket, with the ports of `server.port` and `server.metrics_address`:

    [Unit]
    Description=weed WebDAV server's sockets

    [Socket]
    ListenStream=443
    ListenStream=127.0.0.1:9100

    [Install]
    WantedBy=sockets.target

Then start it, and weed again:

    # systemctl daemon-reload
    # systemctl enable --now weed.socket
    # systemctl restart weed

weed takes the socket of each of its ports, by port, and listens itself on any that systemd does not pass; a socket on another port keeps it from starting. It logs which, and its Landlock rules then let it bind nothing (`tcp="no bind, ..."`):

    level=INFO msg=listening address=[::]:443 scheme=https socket="passed by systemd"

systemd starts weed at the first connection if it does not run: *systemctl stop weed.socket weed* stops both.

### Testing the service {#test-systemd}

*make test-systemd* runs weed as this page installs it, in an AlmaLinux 10 container that boots systemd: the units above with the sandboxing and `Delegate=yes`, as root, and then as an account of its own (below). It checks that weed serves uploads, downloads and third-party copies, reloads, bans, restarts after a crash, and stops with its workers; that weed may write only what the sandboxing allows; that it starts again on its own when a storage is mounted over the exported directory; that it blocks while its storage is unmounted, writing nothing beneath, and serves it again once it is mounted; that with `require_mount` it does not start while the storage is not mounted; that a worker killed for its memory leaves weed serving; and that with weed.socket, a restart refuses no connection. Try other directives with *weed check* and a few requests of each kind, uploads and third-party copies included.

## Without systemd {#without-systemd}

weed does not need systemd: it is a process that serves in the foreground, which any supervisor can run (runit, s6, supervisord, a container's init). What the unit above gives it, it gets otherwise:

| With systemd | Otherwise |
|----|----|
| `Type=notify-reload`: systemd knows when weed is ready, reloading, stopping | weed tells systemd only when NOTIFY_SOCKET is set. Elsewhere, wait for /healthz to answer 200. |
| `systemctl reload` | SIGHUP: weed reopens its log file and reloads its credentials. |
| `systemctl stop` | SIGTERM or SIGINT: weed stops taking requests, and waits up to 30 seconds for those in progress. |
| `Restart=on-failure` | Start weed again when it exits with a status other than 0: 75 when a storage was mounted over the exported directory, so that it is confined to the directory as it now is. |
| weed.socket | weed listens on its ports itself. Supervisors that pass sockets as systemd does (LISTEN_FDS) work too. |
| The journal | weed logs to standard error, or to `server.log_file`. |
| `ExecStartPre=weed check` | Run *weed check* before starting weed. |
| `Delegate=yes`, for `unix_users.cgroups` | weed needs a cgroup v2 directory that it may write, with its controllers: a container's own cgroup namespace, or one that you make for it. |
| ProtectSystem= and the other sandboxing | weed confines itself with Landlock anyway (see [Unix accounts](unix-accounts.html#process)). |

*make interop* and *make test-linux* run weed that way, started from a script in a container; *make test-cgroups* runs its cgroups in a container without systemd.

## Running without root {#without-root}

weed needs root only to start workers as other accounts. It can run as an account of its own with the CAP_SETUID and CAP_SETGID capabilities, and CAP_NET_BIND_SERVICE for port 443 unless systemd listens on it ([socket activation](#socket-activation)). Its workers get none of them. Add to \[Service\]:

    User=weed
    AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE
    RuntimeDirectory=weed
    RuntimeDirectoryMode=0700
    StateDirectory=weed
    StateDirectoryMode=0700

RuntimeDirectory and StateDirectory create /run/weed and /var/lib/weed for that account. The account must be able to read the configuration file and every file it names, the host key included. Without the capabilities, weed does not start:

    level=ERROR msg="cannot start" error="cannot start the worker processes, which access files as Unix accounts: cannot start a worker for nobody: fork/exec /proc/self/exe: operation not permitted (weed must run as root, or with CAP_SETUID and CAP_SETGID)"

## Network

Open the port of weed (`server.port`, 443 in production) to your clients and to the other storage endpoints, which connect to it for third-party copies. Keep the metrics address (`server.metrics_address`) local or on a management network: /metrics and /status need no authentication.

weed accepts TLS 1.2 and later.
