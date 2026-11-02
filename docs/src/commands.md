---
title: 'Commands'
---

weed is a single binary. Options are set in the configuration file, not on the command line: the commands take `-config` only.

    $ weed -h
    usage: weed [-config weed.toml]
           weed check [-config weed.toml]
                          check that weed would start with a configuration, without serving
           weed version   print the version, commit and build of weed
           weed config    print a configuration file with every option and its default
           weed utils     helpers for passwords, app tokens and certificates, and
                          ban, unban and bans for the running weed

    Options are set in the configuration file. Without one, weed serves the current
    directory at http://127.0.0.1:9000/webdav/ to local clients, without authentication,
    as the Unix account nobody, and its metrics, status and dashboard at
    http://127.0.0.1:9000/metrics, /status and /dashboard/. weed runs on Linux,
    as root.

## weed

    # weed -config /etc/weed/weed.toml

Serves until SIGTERM or SIGINT, then stops accepting requests, gives those in progress 30 seconds to finish, and stops its workers. SIGHUP reopens the log file and reloads credentials (see [Reloading](reloading.html)). Under systemd, weed tells systemd when it is ready, reloading and stopping, and its status line, and serves on the sockets that systemd passes, if it does (see [Installation](installation.html#systemd)).

weed runs on Linux, as root or with CAP_SETUID and CAP_SETGID. *weed worker* is how weed starts its worker processes: it is not for running by hand.

| Exit status | When |
|----|----|
| 0 | weed stopped when asked to |
| 1 | weed could not start, or stopped on an error; it says why on standard error and in its log |
| 75 | weed stopped to be started again: a storage was mounted over the exported directory, or in its place (see [Installation](installation.html#mounted)) |
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
