---
title: 'Installation'
---

weed is a single binary, without runtime dependencies. You build it from source with Go, install it, and run it as a systemd service.

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
    After=network-online.target
    Wants=network-online.target

    [Service]
    # systemd 253 or later; before, Type=notify and ExecReload=/bin/kill -HUP $MAINPID
    Type=notify-reload
    ExecStartPre=/usr/local/bin/weed check -config /etc/weed/weed.toml
    ExecStart=/usr/local/bin/weed -config /etc/weed/weed.toml
    Restart=on-failure

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

weed's tests do not cover these: try them with *weed check* and a few requests of each kind, uploads and third-party copies included.

## Running without root {#without-root}

weed needs root only to start workers as other accounts. It can run as an account of its own with the CAP_SETUID and CAP_SETGID capabilities, and CAP_NET_BIND_SERVICE for port 443. Its workers get none of them. Add to \[Service\]:

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
