---
title: 'HTTP endpoints'
---

## On the main port {#main}

| Path | Authentication | What |
|----|----|----|
| /webdav/... | required, unless anonymous | The exported directory, with WebDAV (RFC 4918), checksums (RFC 9530 and 3230) and third-party copy. POST with Content-Type application/macaroon-request asks for a macaroon (see [Authentication](authentication.html#macaroons)). |
| /proc/whoami | as /webdav/ | How weed sees the client: the user, the method, the Unix account, and what the credentials say. |
| /proc/x509 | none | The TLS connection and the certificates that the client presents, with their DN as weed reads it, and whether X.509 authentication would accept them. |
| /auth/oidc | none | The OIDC login page, with `oidc.enabled` (see [Authentication](authentication.html#oidc)). |
| /oidc_redirect | none | Where the issuer sends users back after they log in. |
| /auth/basic | Basic | Asks the browser for a password, with `basic.enabled`. |
| /auth/x509 | X.509 | Checks the client certificate, with `x509.enabled`. |
| /healthz | none | "ok" if the exported directory responds, 503 otherwise (see [Monitoring](monitoring.html#healthz)). |
| / | none | An index page with links to the above. |
| /metrics, /status, /dashboard/ | none | Only without a configuration file, whose clients are local. |

## On server.metrics_address {#metrics-address}

| Path        | What                                                                                  |
|-------------|---------------------------------------------------------------------------------------|
| /           | Leads to /dashboard/.                                                                 |
| /dashboard/ | A dashboard of /status and /metrics, which only reads (see [Monitoring](monitoring.html#dashboard)). |
| /metrics    | Prometheus metrics (see [Metrics](metrics.html)).                                     |
| /status     | What runs, as JSON (see [Monitoring](monitoring.html#status)).                        |
| /healthz    | As on the main port.                                                                  |

None of these require authentication: serve them on localhost or a management network.

## WebDAV methods {#webdav}

| Method | Notes |
|----|----|
| GET, HEAD | Range requests; Repr-Digest or Digest when asked for (Want-Repr-Digest, Want-Digest), if weed stored one when it wrote the file. |
| PUT | Written to a temporary file, renamed into place when complete; verified against Repr-Digest; If-Match and If-None-Match. |
| PROPFIND | Depth 0 and 1; Depth: infinity is refused (403). |
| PROPPATCH | Stores nothing: every property is refused (403) in the 207 answer. |
| MKCOL, DELETE, MOVE | As RFC 4918. |
| COPY | Within weed, or a third-party copy: with Source (pull), or with a Destination on another server (push). See [Third-party copy](tpc.html). |
| LOCK, UNLOCK | Exclusive write locks; shared locks get 501. Locks are per account, and do not survive the account's worker. |
| OPTIONS | DAV: 1, 2. |

## Status codes

| Status | When |
|----|----|
| 401 | no credentials, or credentials that are not valid: wrong password, expired or untrusted token, certificate that is revoked or of an unknown CA |
| 403 | valid credentials that do not allow the request: not in the grid-mapfile, no usable Unix account, scopes or caveats that do not cover it, a banned user; or the filesystem refuses the account |
| 406 | a Repr-Digest without any supported algorithm |
| 412 | an upload that does not match its Repr-Digest; a failed If-Match or If-None-Match; Overwrite: F onto an existing resource |
| 423 | a locked resource |
| 501 | shared locks; third-party copies when disabled, or with credential delegation |
| 503 | no worker for the account (`unix_users.max_workers`), too many third-party copies (`tpc.max_transfers`), with Retry-After; storage not responding (/healthz) |
