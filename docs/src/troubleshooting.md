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
| `cannot start a worker for nobody: fork/exec /proc/self/exe: operation not permitted (weed must run as root, or with CAP_SETUID and CAP_SETGID)` | Run weed as root, or give it the capabilities (see [Installation](installation.html#without-root)). |
| `cannot read the banned users (admin.bans): open /var/lib/weed/bans.json: permission denied` | weed's user must be able to read and write `admin.bans` and its directory. |
| `control plane: /run/weed/admin.sock is in use, by another weed?` | Another weed runs with the same `admin.socket`. Stop it, or give each weed its own. |
| `listen tcp :443: bind: address already in use` | Something else listens on the port: `ss -ltnp 'sport = :443'`. |
| `x509 needs tls`, `oidc needs tokens.issuers, ...` | An option needs another one: set it as weed says. |

With systemd, a failing `weed check` in ExecStartPre stops the start, and *systemctl status weed* shows its message.

## Clients are refused {#refused}

For every refused credential, weed logs "authentication failed" with the method and why, followed by the request's record (see [Logging](logging.html#authentication)). Look the request up by time, client address or user:

    # grep -B1 'status=40[13]' /var/log/weed.log | tail

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

## 503 Service Unavailable {#unavailable}

| weed says | What to do |
|----|----|
| `no worker for the request ... the 256 workers allowed (unix_users.max_workers) are all busy` | More accounts are active at once than workers are allowed: raise `unix_users.max_workers`. |
| `cannot start a worker ...` | The worker could not start: weed logs why, e.g. a failed cgroup limit, or a binary that changed in place (see [Upgrading](upgrading.html#old-binary)). |
| Too many concurrent third-party copies | `tpc.max_transfers` copies are running; clients retry after the Retry-After. Raise it if the network and disks allow. |
| /healthz: storage unavailable, storage not responding | The exported directory cannot be read, or does not answer within 5 seconds: check the filesystem (a hung NFS or a lost mount). |

## Third-party copies fail {#tpc}

The COPY answer ends with "failure: \<reason\>", and weed logs "third-party copy failed" with the same reason. The usual ones:

- A TLS error with the remote endpoint: its CA is not trusted. Set `tpc.ca_path` to /etc/grid-security/certificates.
- The remote endpoint's address is refused (loopback, private): see [Remote endpoints](tpc.html#remote-endpoints). Storage on a private network needs `tpc.allow_private`.
- The remote answers 401 or 403: the credential in TransferHeaderAuthorization is not valid there, or does not allow the path.
- "client/server checksum mismatch": the data received differs from the checksum that the client gave. Nothing was stored.
- The copy stalled for `tpc.stall_timeout`: the remote stopped sending.

## More detail {#debug}

Set `server.log_level = "debug"` and restart, to log how each request was authenticated and which methods were tried. /proc/whoami and /proc/x509 show what weed makes of a client's credentials.
