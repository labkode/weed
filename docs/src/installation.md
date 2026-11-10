---
title: 'Installation'
---

weed is a single binary, which needs no other software than glibc. On AlmaLinux, Rocky Linux or RHEL 10 and later, install its RPM, which sets it up as this page does ([The RPM](#rpm)). Elsewhere, download a release or build it from source with Go, install it, and run it as a systemd service, or under another supervisor (see [Without systemd](#without-systemd)).

| weed needs | |
|----|----|
| Linux 5.19 or later, with Landlock among its security modules (lsm=), and seccomp | as the kernels of EL9 and EL10 have them; weed does not start otherwise, and says why |
| glibc 2.34 or later, for a release's weed | EL9 and EL10, Debian 12, Ubuntu 22.04 and later; a weed built without cgo needs none (see [Building](#building)) |
| systemd 253 or later, for the unit of this page and the RPM | Type=notify-reload: EL10; EL9's systemd is 252 |

weed is developed and tested on AlmaLinux 10 (EL10), which it targets: the RPM is for EL10 alone, and other systems are not tested.

## The RPM {#rpm}

Each release on [GitHub](https://github.com/labkode/weed/releases) has an RPM for EL10 (AlmaLinux, Rocky Linux, RHEL 10 and later), for x86_64 and aarch64:

    # v=1.2.0
    # dnf install https://github.com/labkode/weed/releases/download/v$v/weed-$v-1.el10.x86_64.rpm

| It installs | What |
|----|----|
| /usr/bin/weed | weed, the release's (below) |
| /usr/lib/systemd/system/weed.service | [the unit](#systemd), which runs weed as the account weed |
| /usr/lib/sysusers.d/weed.conf | the account weed and its group, which the RPM makes |
| /usr/lib/sysctl.d/60-weed.conf | net.core.wmem_max and rmem_max of 1 MiB, which the RPM applies (see [Performance](performance.html#socket-buffers)) |
| /etc/weed/weed.toml | a configuration that serves /srv/weed on 127.0.0.1:8080 to the users of /etc/weed/.htpasswd, and the metrics on 127.0.0.1:9180; root:weed, 0640 |
| /etc/weed/.htpasswd, .app-tokens | empty: no one logs in yet; root:weed, 0640 |
| /etc/logrotate.d/weed | the rotation of /var/log/weed/weed.log, for `server.log_file` (see [Logging](logging.html#rotation)) |
| /srv/weed | the exported directory |
| /usr/share/doc/weed/ | README.txt, CHANGELOG.md, and this guide (guide/) |

It neither enables nor starts weed. Each user's requests access the files as the Unix account of the same name: make the account, unless it has one (in LDAP, for one), set the user's password, which *weed utils password* asks for and writes to /etc/weed/.htpasswd, give the account a directory, and start weed:

    # useradd -M alice
    # weed utils password alice
    Password of alice:
    Again:
    Added alice to /etc/weed/.htpasswd (basic.htpasswd of /etc/weed/weed.toml); weed reads it again on systemctl reload weed (SIGHUP), and every server.reload_interval
    # mkdir /srv/weed/alice && chown alice: /srv/weed/alice
    # systemctl enable --now weed
    $ curl -u alice -T notes.txt http://127.0.0.1:8080/webdav/alice/notes.txt

Then set it up for production in /etc/weed/weed.toml, as the file says: HTTPS on port 443 to every interface, X.509 certificates or tokens (see [Getting started](getting-started.html) and [Configuration](configuration.html)). The account weed must be able to read every file that the configuration names, the host key included (`chgrp weed hostkey.pem && chmod 0640 hostkey.pem`). Change the unit with a drop-in (*systemctl edit weed*), not in /usr/lib: an upgrade replaces the unit, and keeps the files of /etc/weed that you changed.

An upgrade does not restart weed. The new version checks the configuration at once, as root and as the account weed, and says whether it would start with it; restart weed when it would (see [Upgrading](upgrading.html)):

    # dnf upgrade https://github.com/labkode/weed/releases/download/v1.3.0/weed-1.3.0-1.el10.x86_64.rpm
    ...
    weed 1.3.0: /etc/weed/weed.toml: weed would start with it (sha256 7c0f...), as the account weed too (User= of weed.service)
    weed: the running weed is the version before, until systemctl restart weed
    # systemctl restart weed

Otherwise dnf shows why, "weed: warning: weed 1.3.0 would not start with /etc/weed/weed.toml, ...": correct the file, check it with *weed check -config /etc/weed/weed.toml*, and restart weed then. The RPM also warns of a unit /etc/systemd/system/weed.service, as an earlier version of this guide had you write, which hides the RPM's: remove it, and keep your changes in a drop-in.

Removing the RPM stops weed. It leaves the account weed, /srv/weed, and what weed wrote in /var/lib/weed and /var/log/weed; the files of /etc/weed that you changed are kept as .rpmsave.

## Releases {#releases}

Each release on [GitHub](https://github.com/labkode/weed/releases) has an archive for linux/amd64 and one for linux/arm64, with weed, README.txt, CHANGELOG.md, LICENSE and this guide (guide/), the RPMs (above), and SHA256SUMS of them all:

    $ v=v1.2.0
    $ curl -fLO https://github.com/labkode/weed/releases/download/$v/weed-$v-linux-amd64.tar.gz
    $ curl -fLO https://github.com/labkode/weed/releases/download/$v/SHA256SUMS
    $ sha256sum --ignore-missing -c SHA256SUMS
    weed-v1.2.0-linux-amd64.tar.gz: OK
    $ tar -xzf weed-$v-linux-amd64.tar.gz
    $ weed-$v-linux-amd64/weed version

Its weed, the RPM's too, is built with cgo on AlmaLinux 10, which weed targets: it looks accounts up as the system does (see [Building](#building)). Read the release's [Changelog](changelog.html) section before installing it over another version (see [Upgrading](upgrading.html#versions)).

## Building {#building}

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

Without the RPM, install weed, make the account that it runs as, and /etc/weed for its configuration, which that account may read:

    # install -m 0755 weed /usr/local/bin/weed
    # useradd -r -U -d /var/lib/weed -s /usr/sbin/nologin weed
    # install -d -m 0750 -g weed /etc/weed

Keep the binary readable and executable by everyone (0755): the workers that run as the users are started from it.

weed reads and writes these, which [Files](files.html) lists in full:

| Path | What |
|----|----|
| /etc/weed/weed.toml | the configuration file, root:weed 0640; weed refuses one that others may read if it holds secrets |
| /etc/weed/issuers.json | the token issuers, if you accept tokens |
| /etc/grid-security/ | the host certificate and key, the CA certificates and CRLs, the grid-mapfile |
| /run/weed/admin.sock | the control plane's socket, which weed creates (see [Banning users](banning.html)) |
| /var/lib/weed/bans.json | the banned users, written by weed at the first ban |

The unit (below) makes /run/weed, /var/lib/weed and /var/log/weed for the account weed. Raise the socket buffers that weed may ask for to 1 MiB, or downloads lose a third of their speed (see [Performance](performance.html#socket-buffers)):

    # printf 'net.core.wmem_max = 1048576\nnet.core.rmem_max = 1048576\n' >/etc/sysctl.d/60-weed.conf
    # sysctl --system

## The systemd service {#systemd}

weed is a notify service: it tells systemd when it is ready (once it listens), when it reloads and when it stops, and keeps its status line current. It runs as the account weed, with the capabilities that starting workers as other accounts needs (see [The account weed](#without-root)). Write /etc/systemd/system/weed.service, the RPM's unit:

    [Unit]
    Description=weed WebDAV server
    Documentation=https://labkode.github.io/weed/
    After=network-online.target remote-fs.target
    Wants=network-online.target
    # Restart= for ever, not 5 times in 10 seconds and then never again
    StartLimitIntervalSec=0

    [Service]
    # systemd 253 or later; before, Type=notify and ExecReload=/bin/kill -HUP $MAINPID
    Type=notify-reload
    ExecStartPre=/usr/local/bin/weed check -config /etc/weed/weed.toml
    ExecStart=/usr/local/bin/weed -config /etc/weed/weed.toml
    # After a crash: in 2 seconds, and up to a minute apart while it keeps failing
    # (RestartSteps=: systemd 254)
    Restart=on-failure
    RestartSec=2s
    RestartSteps=5
    RestartMaxDelaySec=1min
    # A worker that the kernel kills for its memory does not stop weed
    OOMPolicy=continue
    # weed bounds its threads itself, and those of each account with pids.max:
    # systemd's default can be fewer than its workers hold when the storage hangs
    # (see Performance)
    TasksMax=infinity
    # A cgroup for the workers of each account (unix_users.cgroups)
    Delegate=yes
    # weed runs as an account of its own. The starter of its workers keeps CAP_SETUID,
    # CAP_SETGID and CAP_KILL, to start them as their accounts and to kill them; weed
    # itself keeps CAP_NET_BIND_SERVICE alone, for ports below 1024
    User=weed
    Group=weed
    AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_KILL CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_NET_BIND_SERVICE
    # /run/weed for admin.socket, /var/lib/weed for admin.bans, /var/log/weed for
    # server.log_file (see Logging)
    RuntimeDirectory=weed
    RuntimeDirectoryMode=0700
    StateDirectory=weed
    StateDirectoryMode=0700
    LogsDirectory=weed
    LogsDirectoryMode=0750
    # Sandboxing, beyond Landlock and seccomp, which weed applies itself
    ProtectSystem=full
    PrivateTmp=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectKernelLogs=yes
    ProtectClock=yes
    ProtectHostname=yes
    RestrictRealtime=yes
    # Not RestrictSUIDSGID= nor RestrictNamespaces=: their seccomp filters refuse
    # openat2(2), which workers open files with, and clone3(2), which starts each in its
    # cgroup
    LockPersonality=yes
    MemoryDenyWriteExecute=yes
    SystemCallArchitectures=native
    RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6

    [Install]
    WantedBy=multi-user.target

*weed check* reads the configuration and every file it names before weed starts, so that *systemctl start* fails with the reason weed would not start. A restart stops weed before ExecStartPre runs, so run *weed check* yourself before restarting (see [Upgrading](upgrading.html)). Run by root, it checks again as the account weed, with the capabilities of the unit, as ExecStartPre does: root reads a host key of mode 0600, and the account weed does not (see [Commands](commands.html#check)). With Type=notify-reload, *systemctl reload weed* re-reads the credentials (see [Reloading](reloading.html)) and returns once that is done.

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

weed starts again on its own after a crash. While it keeps failing to start, such as while its storage is not mounted (`require_mount`, below), systemd tries again ever less often, every minute at last, and never gives up. With OOMPolicy=continue, a worker that the kernel kills for its memory is one that weed starts again at the account's next request, and the other accounts do not notice; without it, systemd would stop weed as a whole (its default, except with Delegate=yes). Limit the memory of each account (`memory.max` in `unix_users.cgroup_limits`, see [Limits per account](limits.html)): an account that reaches it has its worker killed within its own cgroup, never weed's own process.

`Delegate=yes` gives weed its cgroup, so that each account's workers may run in a cgroup of their own (`unix_users.cgroups`, see [Unix accounts](unix-accounts.html#cgroups)).

### Sandboxing {#sandboxing}

The unit confines weed and its workers together, beyond what weed does itself (see [Unix accounts](unix-accounts.html#confinement)): /usr, /boot and /etc read-only, a /tmp of their own, no kernel tunables, modules or logs, no memory both writable and executable, and sockets of the families that weed opens alone. Unless the exported directory is below /home, confine them further with a drop-in (*systemctl edit weed*). For instance, in \[Service\]:

    # All read-only, but /dev, /proc, /sys, and the directories of RuntimeDirectory=,
    # StateDirectory= and LogsDirectory=
    ProtectSystem=strict
    # The exported directory
    ReadWritePaths=/data
    # Unless the exported directory is below /home
    ProtectHome=yes

weed confines itself with Landlock as well, and each worker to the exported directory (see [Unix accounts](unix-accounts.html#process)). A storage mounted at /data after weed started is writable, as it is mounted.

### A storage mounted at the exported directory {#mounted}

Each worker is confined to the exported directory as it was when the worker started (see [Unix accounts](unix-accounts.html#mounted)), and weed looks at the directory every 5 seconds:

- When the storage that the directory was on, at startup or mounted since, is no longer mounted, so that the directory is on the file system of / again, or gone (a storage mounted above it), weed blocks. Requests get 503, /healthz too, and weed never serves the directory beneath: uploads there would fill the root file system, and be hidden once the storage is back. weed goes on running: `systemctl status weed` says since when it is blocked, /status has `storage_unmounted`, and the metric `weed_storage_unmounted` is 1 (see [Metrics](metrics.html)).
- When a storage is mounted over the directory or in its place, a remount, the storage mounted again after it was lost, or one mounted after weed started, weed replaces its workers: those confined to the directory as it was finish their requests and stop, and the next requests get workers confined to what is there now.

A storage that comes back thus needs no one: weed serves it again within seconds, without restarting.

    level=ERROR msg="the storage of the exported directory is no longer mounted: workers do not start, until it is again" error="the storage that the exported directory /data was on is no longer mounted: ..."
    level=INFO msg="the storage of the exported directory is mounted again: workers start" dir=/data
    level=INFO msg="the exported directory has changed since the worker started (mounted again?): replacing the worker" worker=alice/1630 dir=/data

weed knows that there was a storage only while it runs. One that starts while the storage is not mounted, after a boot where the mount failed, a crash, or `systemctl restart`, serves the directory beneath. If the exported directory is on a storage of its own, mounted at it or above it (NFS, a file system of its own), set `require_mount`, which refuses to serve it from the file system of /:

    [server]
    dir = "/data"
    require_mount = true

weed then does not start while the storage is not mounted, and starts once it is back, as systemd tries again. After=remote-fs.target starts weed after the network file systems at boot; RequiresMountsFor=/data is not needed, and would do more: a mount that fails at boot would fail weed's start, which Restart= does not retry.

### Socket activation {#socket-activation}

With a socket unit, systemd listens on weed's ports and passes the sockets to weed: while weed restarts, after a crash or an upgrade, clients wait in the queue instead of being refused, and weed binds no port, so it keeps no capability (CAP_NET_BIND_SERVICE). Write /etc/systemd/system/weed.socket, with the ports of `server.port` and `server.metrics_address`:

    [Unit]
    Description=weed WebDAV server's sockets

    [Socket]
    ListenStream=443
    ListenStream=127.0.0.1:9180

    [Install]
    WantedBy=sockets.target

Then start it, and weed again:

    # systemctl daemon-reload
    # systemctl enable --now weed.socket
    # systemctl restart weed

weed takes the socket of each of its ports, by port, and listens itself on any that systemd does not pass; a socket on another port keeps it from starting. It logs which, and its Landlock rules then let it bind nothing (`tcp="no bind, ..."`):

    level=INFO msg=listening address=[::]:443 scheme=https socket="passed by systemd"

systemd starts weed at the first connection if it does not run: *systemctl stop weed.socket weed* stops both.

### As root {#root}

weed needs no root (see [The account weed](#without-root)). Where the account weed cannot be given what weed reads, such as a host key that must stay root's alone, run it as root, with a drop-in (*systemctl edit weed*):

    [Service]
    User=root
    Group=root

weed then gives up root's capabilities as it starts, as it does those of the account weed: its starter of workers keeps CAP_SETUID, CAP_SETGID and CAP_KILL, and weed itself none. As root, it owns root's files, but reaches only what Landlock lets it.

### Testing the service {#test-systemd}

*make test-systemd* builds the RPM, and runs weed as it installs it, in an AlmaLinux 10 container that boots systemd (Podman): the unit above as the account weed, with the sandboxing of the drop-in above and `unix_users.cgroups`, then as root. It checks that the RPM makes the account, its files and the unit of this page; that weed serves uploads, downloads and third-party copies, reloads, bans, restarts after a crash, and stops with its workers; that weed has no capabilities and its starter only its three; that a ban stops the user's workers at once; that weed may write only what the sandboxing allows; that a storage mounted over the exported directory is served by the same weed; that it blocks while its storage is unmounted, writing nothing beneath, and serves it again once it is mounted; that with `require_mount` it does not start while the storage is not mounted; that a worker killed for its memory leaves weed serving; that weed does not start under RestrictSUIDSGID= or RestrictNamespaces=, and says so; that *weed check* by root checks as the account weed too; that an upgrade checks the configuration with the new weed, and warns of a unit that hides the RPM's; that logrotate rotates `server.log_file` with the RPM's file; and that with weed.socket, a restart refuses no connection. Try other directives with *weed check* and a few requests of each kind, uploads and third-party copies included.

*make test-vm* runs the same tests on an AlmaLinux 10 virtual machine, of its cloud image: EL10's kernel, rather than the host's, and SELinux enforcing, with its targeted policy, which a container does not have. It then checks that SELinux denied weed, its starter and its workers nothing. It needs qemu with KVM (/dev/kvm); CI runs it, and again on the RPM of each release.

## Without systemd {#without-systemd}

weed does not need systemd: it is a process that serves in the foreground, which any supervisor can run (runit, s6, supervisord, a container's init). What the unit above gives it, it gets otherwise:

| With systemd | Otherwise |
|----|----|
| `Type=notify-reload`: systemd knows when weed is ready, reloading, stopping | weed tells systemd only when NOTIFY_SOCKET is set. Elsewhere, wait for /healthz to answer 200. |
| `systemctl reload` | SIGHUP: weed reopens its log file and reloads its credentials. |
| `systemctl stop` | SIGTERM or SIGINT: weed stops taking requests, and waits up to 30 seconds for those in progress. |
| `Restart=on-failure` | Start weed again when it exits with a status other than 0. |
| `User=weed`, `AmbientCapabilities=` | Run weed as root, or as an account of its own with CAP_SETUID, CAP_SETGID and CAP_KILL in its ambient set (and CAP_NET_BIND_SERVICE for a port below 1024): `setpriv --reuid=weed --regid=weed --init-groups --inh-caps=+setuid,+setgid,+kill --ambient-caps=+setuid,+setgid,+kill weed ...`. |
| /usr/lib/sysctl.d/60-weed.conf | Set net.core.wmem_max and rmem_max to 1048576 (see [Performance](performance.html#socket-buffers)). |
| weed.socket | weed listens on its ports itself. Supervisors that pass sockets as systemd does (LISTEN_FDS) work too. |
| The journal, `LogsDirectory=` | weed logs to standard error, or to `server.log_file`, which keeps every record: the journal drops those beyond its rate limit (see [Logging](logging.html#file)). |
| `ExecStartPre=weed check` | Run *weed check* before starting weed. |
| `Delegate=yes`, for `unix_users.cgroups` | weed needs a cgroup v2 directory that it may write, with its controllers: a container's own cgroup namespace, or one that you make for it. |
| ProtectSystem= and the other sandboxing | weed confines itself with Landlock anyway (see [Unix accounts](unix-accounts.html#process)). |

*make interop* runs weed that way, started from a script in a container.

## The account weed {#without-root}

weed needs root only to start workers as other accounts, and it does not keep it. The unit runs it as the account weed, with three capabilities, in its ambient set so that weed keeps them as it executes:

    User=weed
    Group=weed
    AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_KILL CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_NET_BIND_SERVICE

As it starts, weed starts a process of its own, the starter of workers, which keeps CAP_SETUID and CAP_SETGID, to start workers as their accounts, and CAP_KILL, to stop them; weed itself gives them up, and keeps CAP_NET_BIND_SERVICE alone, if it listens on a port below 1024 ([socket activation](#socket-activation) needs none). Workers get none (see [Unix accounts](unix-accounts.html#process)). The starter can become any account, root too: it is as trusted as root, but it reads no request.

RuntimeDirectory, StateDirectory and LogsDirectory make /run/weed, /var/lib/weed and /var/log/weed for the account. It must be able to read the configuration file and every file that it names, the host key included. Without the capabilities, weed does not start:

    level=ERROR msg="cannot start" error="cannot start the worker processes, which access files as Unix accounts: weed must run as root, or with the capabilities CAP_SETUID, CAP_SETGID and CAP_KILL (systemd: AmbientCapabilities=)"

## Network

Open the port of weed (`server.port`, 443 in production) to your clients and to the other storage endpoints, which connect to it for third-party copies. Keep the metrics address (`server.metrics_address`) local or on a management network: /metrics and /status need no authentication.

weed accepts TLS 1.2 and later.
