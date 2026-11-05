---
title: 'Commands'
---

weed is a single binary. Options are set in the configuration file, not on the command line: the commands take `-config` only, but weed limits, which measures weed.

    $ weed -h
    usage: weed [-config weed.toml]
           weed check [-config weed.toml]
                          check that weed would start with a configuration, without serving
           weed version   print the version, commit and build of weed
           weed config    print a configuration file with every option and its default
           weed limits [-config weed.toml] [-dir DIR]
                          what weed can serve on this machine, and the settings of weed,
                          systemd and the kernel that would let it serve more (root)
           weed utils     helpers for passwords, app tokens and certificates, and
                          ban, unban and bans for the running weed

    Options are set in the configuration file. Without one, weed serves the current
    directory at http://127.0.0.1:9000/webdav/ to local clients, without authentication,
    as the Unix account nobody, and its metrics, status and dashboard at
    http://127.0.0.1:9000/metrics, /status and /dashboard/. weed runs on Linux,
    as root, or as an account of its own with CAP_SETUID, CAP_SETGID and CAP_KILL.

## weed

    # weed -config /etc/weed/weed.toml

Serves until SIGTERM or SIGINT, then stops accepting requests, gives those in progress 30 seconds to finish, and stops its workers. SIGHUP reopens the log file and reloads credentials (see [Reloading](reloading.html)). Under systemd, weed tells systemd when it is ready, reloading and stopping, and its status line, and serves on the sockets that systemd passes, if it does (see [Installation](installation.html#systemd)).

weed runs on Linux, as root, or as an account of its own with the capabilities CAP_SETUID, CAP_SETGID and CAP_KILL (see [Installation](installation.html#without-root)). *weed starter* and *weed worker* are how weed starts the process that starts its workers, and its workers (see [What runs](what-runs.html)): they are not for running by hand.

| Exit status | When |
|----|----|
| 0 | weed stopped when asked to |
| 1 | weed could not start, or stopped on an error, such as the end of the process that starts its workers; it says why on standard error and in its log |
| 2 | an unknown command-line option (the usage is printed) |

## weed check {#check}

    # weed check -config /etc/weed/weed.toml
    /etc/weed/weed.toml: weed would start with it (sha256 6794c30b95c0972e5a032630bb90ccdf474c3df01a9dd983f88c9fdc5baf417e)

Checks that weed would start with a configuration, without serving: it reads the file and every file it names, contacts the OIDC provider, and starts a worker as nobody, as weed does at startup. It prints the warnings weed would log, and the SHA-256 of the file, which weed logs and reports when it runs it. It does not try the listening addresses, nor set cgroups up. Run it as the user weed runs as, so that it reads the files with the same permissions. See [What runs](what-runs.html#check).

| Exit status | When |
|----|----|
| 0 | weed would start with the configuration |
| 1 | it would not: `weed would not start with <file>: <why>` on standard error |
| 2 | an unknown command-line option |

## weed limits {#limits}

    # weed limits -rtt 100ms
    ...
    What weed served
      get-small      54886 req/s with 256 clients, p99 17ms; 3358 req/s per core weed used
                     Limit: the CPUs, all busy (weed 16.3 cores, stress 3.1, of 24 CPUs (12 cores))
    ...
    What it cannot do, as set
      - log every request to the journal: it keeps some 333 lines a second, weed
        answered 54886
      - take 3543 new connections a second for long: connection tracking holds 2185
    ...
    What weed limits suggests (it changed nothing)
      - sysctl.d/90-weed.conf: net.netfilter.nf_conntrack_max = 1048576 (was
        262144): the firewall tracks each connection until 120 s after it closes:
        262144 entries hold 2185 new connections a second, and weed took 3543. An
        entry takes some 300 bytes of the kernel's memory: 300 MiB when all are in
        use. Rather than tracking them, a rule of the firewall can leave weed's port
        untracked (nftables: notrack)
      - sysctl.d/90-weed.conf: net.netfilter.nf_conntrack_buckets = 1048576 (was
        262144): the hash table that finds the entries has 262144 buckets: 1048576
        entries would be 4 to a bucket, on a list walked to find one. As many
        buckets as entries, the kernel's default, take 8 MiB
    ...

Finds what weed can serve on its machine, as its configuration sets it, and suggests the settings of weed, systemd and the kernel that would let it serve more. It changes nothing on the machine. It writes what it found, and files of the settings it suggests, for you to review and install. [Performance](performance.html#stress) lists what it checks.

It runs a weed of its own: the same executable, with the settings of the configuration that set what serving costs, on ports of 127.0.0.1. Those settings are the authentication methods, TLS and the kind of host key, the limits of `unix_users`, and logging. That weed uses credentials made for it: a CA, a host certificate, a client certificate, a password, and tokens of an issuer that weed limits serves itself. It exports a directory that weed limits makes in weed's storage and removes at the end. Then weed limits:

1. measures the storage by itself: the end of an upload (a write, two fsyncs and a rename), how many calls it answers at once, a large write;
2. puts its weed under a load that grows until weed or the machine gives (test/stress). The load reads, writes and lists small files, opens new connections, downloads and uploads large files, and authenticates with each method of the configuration. With Basic authentication, it authenticates by an app token, which weed checks without bcrypt, and measures passwords on their own (auth-basic): a bcrypt check for each request would be all it measured. Of a configuration that enables no method, it uses a WLCG token, an app token and a password, and with TLS, a certificate;
3. reads what the kernel dropped meanwhile (connections refused for a full listen queue, connection tracking), what weed's cgroups refused, and weed's warnings and errors;
4. compares what it found with the settings of systemd, journald and the kernel.

It needs root, as weed does, and takes 10 to 20 minutes. Run it before weed serves, or while it serves little: the load takes CPUs, memory and the storage from the weed that serves. It refuses to start while that weed has more than 10 requests in progress. It runs its weed in a systemd scope of its own, with its workers in cgroups as the configuration says. Without systemd it runs it as a child, and does not measure weed's CPU and memory.

| Option | |
|----|----|
| `-config FILE` | weed's configuration, by default /etc/weed/weed.toml if there is one. `-config ""` is none: weed limits then enables every authentication method, and TLS |
| `-dir DIR` | the storage to measure; by default, `server.dir` of the configuration. weed limits works in a directory of its own below it |
| `-account NAME` | the account that the load is made as, by default nobody. It must be able to enter DIR |
| `-out DIR` | where to write; by default, weed-limits in the current directory |
| `-rtt DURATION` | the round trip to weed's farthest clients, e.g. 150ms: weed limits sizes the kernel's TCP buffers for them |
| `-bandwidth RATE` | weed's bandwidth to its clients, in bits a second, e.g. 10G; by default, that of its fastest network interface |
| `-quick` | a load of up to 8 clients and a short measure of the storage, in a minute or two: to check that weed limits works, not to find limits |
| `-force` | run although weed has more than 10 requests in progress |
| `-no-probe` | do not measure the storage by itself |
| `-unit NAME` | weed's systemd unit, by default weed.service |
| `-- ...` | options of the load, e.g. `-- -scenarios download,upload -max 64` (see *weed limits -h*) |

It writes these files to `-out`, and only those of the settings it suggests:

| File | |
|----|----|
| summary.txt | what weed served, what the storage did by itself, what the kernel dropped, what weed cannot do as set and why, and what weed limits suggests; also printed |
| limits.json | all of it, as JSON |
| stress.txt, stress.json | the load, step by step |
| weed.toml | the configuration with the settings it suggests. Each one sits under a comment that says why, and what it was; the rest of the file is unchanged. Compare it with *diff -u* |
| sysctl.d/90-weed.conf | settings of the kernel, for /etc/sysctl.d |
| modules-load.d/weed.conf | modules to load at boot, for /etc/modules-load.d |
| weed.service.d/limits.conf | a drop-in of weed's unit, for /etc/systemd/system |

The summary ends with the commands that install each file. Its numbers vary from one run to the next, by some 10%, and more where the storage writes back in the background what the load wrote. A kind of request that stopped early can be measured again on its own, e.g. `weed limits -no-probe -- -scenarios download`.

| Exit status | When |
|----|----|
| 0 | it ran, and wrote what it found |
| 1 | it could not run, or the load could not set a scenario up; it says why |
| 2 | an unknown command-line option |
| 130 | interrupted (Ctrl-C): it stops its weed, removes its directory, and writes what it found until then |

## weed config {#config}

    $ weed config >weed.toml

Prints a configuration file that sets every option to its default, with what each option does. [Configuration options](options.html) lists the same.

## weed version {#version}

    $ weed version
    weed v1.2.0
    commit   46a37813bc81d7a1b9a8b1e2a9e1f3c3e6c2a0d4 (2026-10-28T16:07:11Z)
    go       go1.27.3 linux/amd64
    build    go:2CX-x4_-THjPR2Dy4JCE/TtMef8lUxfkIJsGhiXwh/3-NbDYhNvYZpdojQpjfp/Dg3...

Prints the version, the commit it was built from and its time, the Go version and platform, and the build ID. See [What runs](what-runs.html#version).

## weed utils {#utils}

    $ weed utils
    Usage: weed utils <command>

    Available commands:
      cert     - Generate TLS certificates
      password - Generate password hashes
      token    - Manage application tokens

    Commands of a running weed, through its control plane (admin.socket):
      ban      - Ban a user: refuse its requests, stop its worker processes
      unban    - Lift the ban of a user
      bans     - List the banned users

    weed utils <command> -h describes a command.

### weed utils ban {#ban}

    Usage: weed utils ban [options] <user>

    Options (before the arguments):
      -config string
            the configuration file that weed runs with, which names the socket (admin.socket)
      -reason string
            why, kept with the ban
      -socket string
            the control plane's socket (default /run/weed/admin.sock)

    # weed utils ban -reason 'compromised credentials' alice
    banned alice; stopped its 1 worker process(es)

Bans a user of the running weed: refuses their requests whatever their credentials, and stops their worker processes. See [Banning users](banning.html).

### weed utils unban {#unban}

    Usage: weed utils unban [options] <user>

    # weed utils unban alice
    lifted the ban of alice

Takes `-config` and `-socket`, as ban does.

### weed utils bans {#bans}

    Usage: weed utils bans [options]

    # weed utils bans
    USER   SINCE                    BY              REASON
    alice  2026-10-29 09:06:57 UTC  uid 0, pid 203  compromised credentials

Lists the banned users; `-json` prints weed's answer as JSON. Takes `-config` and `-socket`, as ban does.

ban, unban and bans exit with:

| Exit status | When |
|----|----|
| 0 | done |
| 1 | weed cannot be reached, did not answer within a minute, or refused; or the change applies with a warning: it could not be saved, or a banned user's worker does not exit (see [Banning users](banning.html)). `weed utils: <why>` on standard error |
| 2 | wrong options or arguments (the usage is printed) |

### weed utils password {#password}

    # weed utils password bob 's3cret'
    Added user 'bob' to .htpasswd

Adds a user with a bcrypt hash of the password to .htpasswd, in the current directory. The password is on the command line, where other users can see it with *ps*, and goes to the shell's history: on a shared host, use `htpasswd -B`, which asks for it.

### weed utils token {#token}

    # weed utils token generate bob
    Generated token for user 'bob': 23bb59e76eeeb0228d5a1d1b53f6bda289ce9e43fae29b85d64215d5422a5127
    Token saved to .app-tokens

Generates a random app token for a user, which they give as their password with Basic authentication, and adds it to .app-tokens, in the current directory. See [Authentication](authentication.html#basic).

### weed utils cert {#cert}

    $ weed utils cert
    Generated server.crt and server.key

Generates a self-signed certificate for localhost and 127.0.0.1, valid for a year, and its key, as server.crt and server.key (mode 0600) in the current directory: for tests, not for clients to trust.
