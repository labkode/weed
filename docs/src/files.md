---
title: 'Files'
---

The files that weed reads and writes, with the paths of the examples in this guide. The options name them; none has a default location except those marked.

| File | Option | Who | What |
|----|----|----|----|
| /usr/local/bin/weed |  | root, 0755 | The binary. Replace it, do not write into it (see [Upgrading](upgrading.html)). |
| /etc/systemd/system/weed.service |  | root, 0644 | The unit (see [Installation](installation.html#systemd)). |
| /etc/systemd/system/weed.socket |  | root, 0644 | The sockets that systemd listens on for weed, if you use them (see [Installation](installation.html#socket-activation)). |
| /etc/weed/weed.toml | `-config` | root, 0600 if it holds secrets | The configuration, read at startup. |
| /etc/grid-security/hostcert.pem, hostkey.pem | `tls.cert`, `tls.key` | root; the key 0400 | The host certificate and key, reloaded. |
| /etc/grid-security/certificates/ | `x509.ca`, `x509.crl_path`, `tpc.ca_path` | readable by all | CAs and CRLs, kept current by fetch-crl, reloaded. The workers read `tpc.ca_path` as their accounts. |
| /etc/grid-security/grid-mapfile (default) | `x509.gridmap` | root, 0644 | DNs and their accounts, reloaded. |
| /etc/weed/issuers.json | `tokens.issuers` | root, 0644 | Token issuers and their users rules, reloaded. |
| /etc/weed/htpasswd, /etc/weed/app-tokens | `basic.htpasswd`, `basic.app_tokens` | root, 0600 | Passwords and app tokens, reloaded. |
| /etc/weed/limits.json | `unix_users.limits` | root, 0644 | The limits of some users and groups, reloaded (see [Limits per account](limits.html#file)). |
| /var/log/weed.log | `server.log_file` | weed | The log, reopened on SIGHUP (see [Logging](logging.html#rotation)). |
| /run/weed/admin.sock (default) | `admin.socket` | weed, 0600 in a 0700 directory | The control plane (see [Banning users](banning.html#control-plane)), removed when weed stops. |
| /var/lib/weed/bans.json (default) | `admin.bans` | weed, 0600 in a 0700 directory | The banned users, written by weed, read at startup. |
| /data/ | `server.dir` | the accounts | The exported directory, accessed as the users' accounts. |
| .weed-upload-\* |  | the accounts | Uploads in progress, in the target directory, renamed into place when complete (see [Storage](storage.html)). |
| user.weed.digest.\<alg\> |  | the accounts | Extended attributes of the files that weed wrote: their checksums (see [Storage](storage.html#checksums)). |

weed writes nothing else. It needs no database, and keeps no sessions: OIDC logins in progress are in a browser cookie, and WebDAV locks are in the memory of the workers.
