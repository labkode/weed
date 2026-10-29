---
title: 'Introduction'
---

weed, the WEbdav Exporter Daemon, exports a directory of a Linux server over WebDAV for the clients and services of the WLCG: gfal2, davix, FTS, Rucio and XRootD, and plain curl. It implements HTTP third-party copy (TPC) in both directions, and verifies checksums from end to end.

This guide is for the administrators who install and run weed. It explains how weed works, how to configure it, and how to operate it: what it logs and measures, how to change credentials while it runs, how to upgrade it, and how to stop a user at once.

## How weed works

weed is one binary. It runs as root and listens on one port, normally with HTTPS. For each request, it:

1.  authenticates the client, with an X.509 certificate or proxy, a WLCG or SciTokens bearer token, a macaroon or a password;
2.  maps the identity to a local Unix account: the grid-mapfile does it for certificates, the token issuer's rules for tokens;
3.  checks that the credentials allow the request (token scopes, macaroon caveats);
4.  hands the request to the *worker process* of that account, which serves it.

A worker runs as its account, with the account's groups, without capabilities and without any way to gain privileges. The kernel checks every file access as for that user, new files belong to whoever wrote them, and *ps* shows who is doing what:

    $ ps -o user,pid,ppid,args -C weed
    USER         PID    PPID COMMAND
    root         812       1 weed -config /etc/weed/weed.toml
    alice       1630     812 weed worker alice
    cms001      1702     812 weed worker cms001

weed itself never opens the exported files: it terminates TLS, authenticates and forwards. A worker starts with the first request of its account, and stops when the account has been idle for a while. See [Unix accounts](unix-accounts.html).

weed is made so that nothing changes by surprise while it runs. It says which build runs, since when and with which configuration, and whether a restart would change any of it ([What runs](what-runs.html)). Credential files are re-read without a restart, and a file that cannot be read keeps its previous contents ([Reloading](reloading.html)). Every request is logged once, with the account it ran as ([Logging](logging.html)).

## What you need

- A Linux server. weed serves on Linux only. On other systems, only its helpers work (*weed utils*, *config*, *check* and *version*).
- root, or the CAP_SETUID and CAP_SETGID capabilities, to start workers as other accounts.
- A local account for every user, in /etc/passwd or in a directory (LDAP, SSSD) that the system's user database reaches.
- For a grid storage node: a host certificate, the IGTF CA certificates in /etc/grid-security/certificates kept current by fetch-crl, a grid-mapfile, and the token issuers of your communities.

## What weed is not

weed serves a directory: it has no namespace database, no tape, no quotas and no replication. It relies on the filesystem for all of that, and on cgroups to limit what each account uses. Some features are not implemented:

- X.509 credential delegation for third-party copies (Credential: gridsite). Pass tokens or macaroons in TransferHeaderAuthorization instead.
- Authorization by token groups alone: a token needs storage scopes, even when its groups choose its account.
- WebDAV locks across accounts: each worker keeps its own.
- Shared locks, dead properties (PROPPATCH stores nothing) and the entity tags of If headers. WLCG clients do not use them.

## About this guide {#conventions}

Commands that start with `#` are run as root, those that start with `$` as any user. The examples use the host weed.example.org, the token issuer https://iam.example.org/, and the accounts alice and cms001. An option is written section.key: `tpc.max_transfers` is the key max_transfers of the \[tpc\] section of the configuration file. The outputs of weed were recorded from it. Lines of the log are shown as they are written, one record per line, even when they are long.

Start with [Installation](installation.html) and [Getting started](getting-started.html). The Reference pages list every command, option, metric, endpoint and file. README.txt, in the source tree, covers the same ground for developers, with the tests.
