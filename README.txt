WEED: WEbdav Exporter Daemon

WEED exports a local directory over WebDAV (RFC 4918) under /webdav/, and implements
WLCG HTTP third-party copy (pull and push) with the data-integrity extension described
in https://github.com/labkode/wlcg-tpc. Clients authenticate with X.509 certificates
and proxies, WLCG/SciTokens bearer tokens (which browsers can get from an OIDC login
page), macaroons or passwords.

Runs on Linux, macOS and Windows (checksum caching in extended attributes on Linux and
macOS only).

    go build && ./weed

serves the current directory at http://127.0.0.1:9000/webdav/ to local clients,
without authentication. Anything else is set in a configuration file:

    ./weed config >weed.toml     every option, its default and what it does
    ./weed -config weed.toml

Helpers:

    ./weed utils password <user> <password>   add a bcrypt entry to .htpasswd
    ./weed utils token generate <user>        create an app token in .app-tokens


Configuration

A TOML file, in which every option is optional, for example:

    [server]
    port = 443
    dir = "/data"
    metrics_address = "localhost:9100"

    [tls]
    enabled = true
    cert = "/etc/grid-security/hostcert.pem"
    key = "/etc/grid-security/hostkey.pem"

    [x509]
    enabled = true
    ca = "/etc/grid-security/certificates"
    crl_path = "/etc/grid-security/certificates"

    [tokens]
    issuers = "/etc/weed/issuers.json"

    [tpc]
    enabled = true
    ca_path = "/etc/grid-security/certificates"

The sections are server, tls, x509, basic, oidc, macaroons, tokens, tpc and
unix_users; below, section.key names an option (e.g. tpc.max_transfers). Unknown
sections and keys are errors, so a misspelt option stops weed instead of being
ignored. Durations are strings such as "90s", "10m" or "24h". weed refuses to read a
file that holds secrets (macaroons.secret_key, oidc.client_secret) if every user can
read it. Changes to the file take effect on restart.

server.anonymous serves requests without credentials, read-write, as the user
"anonymous". It is the default without a configuration file, and weed only allows it
when server.address is a loopback address, so only local clients (any local user)
reach it. Credentials that an enabled method rejects still get 401.


Storage guarantees

* Uploads (PUT, local COPY, TPC pull) are written to a hidden temporary file in the
  target directory, fsynced, and renamed into place only once complete and verified.
  An interrupted or failed upload never replaces or truncates an existing file.
  Temporary files (".weed-upload-*") are invisible to WebDAV clients.
* LOCKs are honoured by every write, including PUT and TPC pull.
* MOVE overwrites by default, as RFC 4918 requires; COPY or MOVE of a collection onto
  itself or into one of its descendants is refused (403).
* PROPFIND with Depth: infinity (or no Depth) is refused (403).
* Paths with encoded dot segments ("%2e%2e") are refused.


Checksums (RFC 9530 Repr-Digest, and legacy RFC 3230 Digest)

Supported algorithms: adler (alias adler32), crc32c, md5, sha, sha-256, sha-512.
Checksums computed during an upload are cached in an extended attribute
(user.weed.digest.<alg>), invalidated when the file's size or mtime changes.

PUT with a Repr-Digest header, e.g. "adler=:AAAAAQ==:, md5=:1B2M2Y8AsgTpgAmY7PhCfg==:"

CONDITION                                                  HTTP CODE
* header absent                                         => upload is not verified
* header malformed                                      => 400 (Bad Request)
* header empty, or none of its algorithms is supported  => 406 (Not Acceptable)
* a supported digest differs from the received data     => 412 (Precondition Failed)
                                                           and the file is not stored
* all supported digests match                           => 201 / 204, with Repr-Digest

GET and HEAD return Repr-Digest when asked with Want-Repr-Digest (e.g. "adler=9"),
and Digest when asked with the legacy Want-Digest (e.g. "adler32").

How to compute a digest in the expected encoding:
    openssl dgst -md5 -binary myfile | base64


Third-party copy (tpc.enabled)

The server receiving the COPY is the active party: it performs the transfer itself and
answers 202 with a "text/perf-marker-stream" body. The body holds a performance marker
every tpc.marker_interval and ends with "success: Created" or "failure: <reason>".
Headers named TransferHeader<Name> are forwarded to the remote as <Name>.

Pull (copy a remote file here):
    curl -X COPY https://weed.example/webdav/dest/file \
        -H 'Source: https://remote.example/path/file' \
        -H 'TransferHeaderAuthorization: Bearer <token for remote>' \
        -H 'Repr-Digest: adler=:<base64>:'

Push (copy a local file to a remote):
    curl -X COPY https://weed.example/webdav/src/file \
        -H 'Destination: https://remote.example/path/file' \
        -H 'TransferHeaderAuthorization: Bearer <token for remote>' \
        -H 'Repr-Digest: adler=:<base64>:'

Data integrity:
* Pull sends "Want-Repr-Digest: adler=9" to the source. If the source reports a
  digest that contradicts the client's, the copy fails before any data is stored.
  Whatever the source reports, the received bytes are always checksummed locally and
  compared with the client's digest; on mismatch the file is not saved and the
  stream ends with "failure: file not saved: client/server checksum mismatch ...".
* Push forwards Repr-Digest on the PUT; a 412 from the destination is reported as
  "client/server checksum mismatch reported by destination".
* A source response without Content-Length or chunked framing, with a
  Content-Encoding, or one that stalls for tpc.stall_timeout, fails the copy.

Pre-flight errors (no transfer started): 400 bad Source/Destination or scheme, 404/405
push of a missing file or a collection, 405 pull onto a collection, 409 missing parent,
412 Overwrite: F onto an existing file, 423 target locked, 501 TPC disabled or
credential delegation requested (only "Credential: none" is supported), 503 too many
concurrent transfers (tpc.max_transfers).

Remote endpoints must be https:// (unless tpc.allow_http). So that a COPY cannot be
used to reach services inside the site, each address a remote resolves to is checked
when connecting (also after redirects):
* refused unless tpc.allow_local: loopback, link-local, multicast, 0.0.0.0/8
* refused unless tpc.allow_private: private (RFC 1918, fc00::/7), shared (100.64/10)
  and other special-purpose ranges (RFC 6890), and IPv6 forms embedding IPv4
  addresses (NAT64, 6to4, Teredo); IPv4-mapped IPv6 addresses count as IPv4
* always refused: the unspecified address
Redirects are followed (at most 10, never to http:// when that is not allowed, never
when they change the method). Set tpc.ca_path = "/etc/grid-security/certificates" to
trust IGTF CAs for remote endpoints.

With WLCG tokens, the client passes one token for weed (Authorization) and one for
the remote (TransferHeaderAuthorization); gfal2 does this with BEARER_TOKEN set.


Authentication

Methods are tried in this order; the first one that applies decides. A request that
presents bad credentials gets 401, or 403 if the credentials are valid but not allowed
to do what was asked. Every identity has a username; with unix_users it must be a
local account, which the request then accesses files as (see Unix accounts below).
Without it, all authenticated users have weed's own access to the files.

1. X.509 client certificates ([tls] and [x509]: enabled, ca, gridmap)
   x509.ca is a PEM file or a directory such as /etc/grid-security/certificates.
   End-entity certificates and RFC 3820 (and legacy Globus) proxy chains are accepted.
   The DN, in OpenSSL format and certificate order (e.g.
   "/DC=ch/DC=cern/OU=Users/CN=jdoe"), must be listed in the grid-mapfile, which
   maps it to a user: a certificate from a trusted CA whose DN is not listed gets 403,
   so trusting all of /etc/grid-security/certificates does not let in every grid user.
   With X.509, weed does not start without a readable grid-mapfile; removing a DN
   from it and reloading revokes that user's access.
   /proc/x509 shows how the server sees the presented certificate.

   Proxy chains are refused when a proxy:
   * has a policy other than inherit-all or limited (e.g. independent),
   * is followed by more proxies than its path length allows,
   * is unrestricted but issued by a limited proxy,
   * is legacy and RFC 3820 in the same chain,
   * is expired or not yet valid, or its issuer lacks the digitalSignature key usage.
   Limited proxies are accepted (they are meant for data access).

   Revocation (x509.crl_path; x509.crl_mode "require" or "if-valid"): CRLs, PEM or
   DER, are read from a file or a directory such as /etc/grid-security/certificates,
   where fetch-crl keeps them (<hash>.r0). A certificate is checked against the newest
   current CRL signed by its issuer. With crl_mode "require" (the default) a
   certificate whose issuer has no current CRL is refused, so an expired CRL fails
   closed; with if-valid, certificates are only checked against the CRLs that are
   present and current.

2. WLCG and SciTokens bearer tokens (tokens.issuers = "<file>")
   JWTs from the issuers listed in the file, as defined by the WLCG Common JWT
   Profiles (https://doi.org/10.5281/zenodo.3460258) and SciTokens:

    [{"issuer": "https://wlcg.cloud.cnaf.infn.it/",
      "audiences": ["https://weed.example:443"],
      "base_path": "/wlcg"}]

   The signature is checked against the keys the issuer publishes (found through
   /.well-known/openid-configuration, or oauth-authorization-server). Keys are cached,
   refetched every hour, and fetched at most once a minute per issuer, so forged
   tokens cannot make weed flood an issuer. If the issuer is down, the known keys keep
   working for 2 days after they were last fetched (as the profile recommends); then
   its tokens get 401 until it is back. Use tokens.ca_path to trust CAs other than
   the system's for the issuers. A token must not be expired (1 minute of clock skew
   is allowed), its aud must include one of the audiences or
   https://wlcg.cern.ch/jwt/v1/any, and its wlcg.ver, if it has one, must be 1.x
   (later minor versions are accepted; SciTokens have no wlcg.ver); otherwise 401.

   Scopes grant access to a path and everything below it; paths are relative to the
   issuer's base_path (default "/"), which is relative to the exported directory:
     storage.read:<path>    read, list and stat (also SciTokens read)
     storage.create:<path>  create files and directories, rename, stat; never
                            replace or delete data: PUT, COPY/MOVE and TPC pull onto
                            an existing file get 403, before any data is sent
     storage.modify:<path>  also overwrite and delete (also SciTokens write)
   A path ending in "/" is a directory: storage.create:/a/b/ allows creating the
   directory /a/b and anything inside it, but not a file named /a/b (403); without the
   "/", /a/b may be either. storage.stage and storage.poll are for tape and grant
   nothing (since version 1.1 of the profile, stage does not include read). A
   storage.* scope without a path makes the token invalid (401), as the profile
   requires; SciTokens read and write without a path mean "/". Tokens without storage
   scopes get 403: groups (wlcg.groups) choose an account (see users below) but grant
   nothing by themselves.
   A macaroon cannot be requested with a token, since it would not be bound by the
   token's scopes.

   A token's username is its sub claim, unless the issuer has "users" rules, which
   map tokens to accounts; the first rule that matches decides, and a token that no
   rule matches gets 403:

    "users": [{"sub": "3f2a...", "user": "jdoe"},
              {"group": "/cms/production", "user": "cmsprod"},
              {"sub": "9c1e...", "group": "/cms", "user": "cmsuser"},
              {"user": "cmsguest"}]

   A rule matches tokens whose sub equals its "sub" and whose wlcg.groups contains its
   "group" (exactly: /cms does not match /cms/production); an omitted field matches
   any token, so a rule with only "user" is a default.

   Access required per request:
     GET                      read
     HEAD, PROPFIND Depth: 0  read, create or modify
     PROPFIND Depth: 1        read
     PUT                      create (new files only) or modify
     MKCOL, LOCK, UNLOCK      create or modify
     DELETE, PROPPATCH        modify
     COPY (local)             read on the source; create or modify on the destination
     MOVE                     create or modify on source and destination
     COPY (TPC pull)          create or modify
     COPY (TPC push)          read

   Getting a token in a browser ([oidc]: enabled, issuer, client_id, client_secret,
   redirect_url = "https://<host>/oidc_redirect", scopes, audience)
   At /auth/oidc users log in at the identity provider, which must be one of the
   token issuers (weed does not start otherwise), and get a page showing the access
   token it issued, the account weed serves it as, its scopes and expiry, and how to
   use it with curl and gfal2. The token is checked as above before it is shown: a
   token weed would refuse is not given out, and the page says why. Logins ask for
   oidc.scopes (default openid and storage.read:/; the issuer grants those its
   policies allow) and, if set, oidc.audience (the "audience" parameter of INDIGO
   IAM), which should be one of the issuer's audiences. For tokens that renew
   themselves, use oidc-agent instead.

   weed keeps no sessions: requests carry the token, and a login in progress (its
   OAuth2 state and PKCE verifier) is in a cookie of the browser, which is used once
   and, over HTTPS, is a __Host- cookie that other hosts of the domain cannot set.
   Any node with the same configuration completes a login that another started.

3. Macaroons ([macaroons]: enabled, secret_key)
   Any authenticated user can mint a macaroon for a path by POSTing to that path:

    curl -u user:pass -X POST https://weed.example/webdav/dir_0/dir_1/ \
        -H 'Content-Type: application/macaroon-request' \
        -d '{"caveats": ["activity:DOWNLOAD,LIST"], "validity": "PT1H"}'
    => {"macaroon": "<token>", "expires_in": 3600}

   Use it with "Authorization: Bearer <token>". The token is valid only for that path
   and below, and always expires: validity defaults to and is capped at
   macaroons.max_validity (24h). Minting with a macaroon yields an attenuated copy that
   keeps every restriction of the original.

   Caveats a client may request:
     activity:<A>[,<A>...]   DOWNLOAD, UPLOAD, LIST, MANAGE, DELETE, READ_METADATA,
                             UPDATE_METADATA (and legacy READ)
     path:<path>             narrow the path further
     before:<RFC 3339 time>  expire sooner
     ip:<ip or CIDR>[,...]   restrict client addresses
   Unknown caveats are rejected when minting and when verifying.

   Activities required per request:
     GET                      DOWNLOAD
     HEAD                     DOWNLOAD, LIST or READ_METADATA
     PROPFIND Depth: 0        DOWNLOAD, LIST or READ_METADATA
     PROPFIND Depth: 1        LIST or READ_METADATA
     PUT                      UPLOAD
     MKCOL                    MANAGE or UPLOAD
     DELETE                   DELETE
     PROPPATCH                UPDATE_METADATA or MANAGE
     LOCK, UNLOCK             UPLOAD or MANAGE
     COPY (local)             DOWNLOAD on the source, UPLOAD on the destination
     COPY (TPC pull)          UPLOAD
     COPY (TPC push)          DOWNLOAD
     MOVE                     MANAGE on source and destination

4. HTTP Basic ([basic]: enabled, htpasswd, app_tokens)
   Passwords are checked against bcrypt entries in the htpasswd file, or against app
   tokens. Basic credentials are sent in clear text without TLS.

/proc/whoami shows the identity a request authenticates as, and its Unix account.

Usernames come from: the grid-mapfile (X.509), the htpasswd or app tokens file
(Basic), the issuer's users rules or sub (tokens), and the minting user (macaroons).


Unix accounts (unix_users)

With unix_users.enabled (Linux only), every identity must be the name of a local
account, looked up with the system's user database (/etc/passwd, or LDAP and SSSD
through NSS when weed is built with cgo); an identity without one, or that names
root, gets 403. weed itself then never touches the exported files: it terminates TLS,
authenticates each request and hands it to the worker process of the account, which
runs as the account (UID, GID and supplementary groups) with no capabilities and
no_new_privs. The kernel checks permissions and ACLs as for the user, new files and
directories belong to the user, and third-party copies read and write the local file
as the user. Token scopes and macaroon caveats are checked by weed before a request
is handed on.

    $ ps -o user,pid,ppid,args -C weed
    USER       PID  PPID COMMAND
    root       812     1 weed -config /etc/weed/weed.toml
    alice     1630   812 weed worker alice
    cms001    1702   812 weed worker cms001

A worker starts with the first request of its account and stops after
unix_users.idle_timeout (default 10m) without one; a worker that dies is replaced on
the next request. At most unix_users.max_workers (default 256) take requests; when
they are all busy, requests of other accounts get 503. Workers log through weed,
their records marked worker.user=alice worker.pid=1630 (see Logging). Each worker
checks that all its threads run as the account, with no capabilities and
no_new_privs, and refuses to serve otherwise; weed starts one as nobody (65534) at
startup to find problems before the first request. Workers get none of weed's
environment.

Workers always run the same build as weed. They are started from /proc/self/exe,
weed's own binary even after an upgrade has replaced it on disk, so a new version
only runs once weed is restarted (until then, ls -l /proc/<pid>/exe shows the old
binary as deleted, for weed and its workers alike). Each worker also reports the Go
build ID of its binary, which the linker derives from its content, and weed refuses
workers whose build is not its own: if the binary is overwritten in place, new
workers are refused (logged as "cannot start a worker", with both builds; requests
get 503) until weed is restarted. The binary must be readable and executable by the
users, as it normally is (0755).

weed talks HTTP to its workers over socket pairs: nothing else can connect to them,
so they trust the identity weed states in request headers (headers of the same names
sent by clients are dropped). They report their metrics back to weed, which serves
them; tpc.max_transfers bounds the copies of all accounts together.

weed must run as root, or with the CAP_SETUID and CAP_SETGID capabilities, for
example in a systemd unit:

    User=weed
    AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE
    Delegate=yes        # for unix_users.cgroups

Downloads relayed from workers run at ~95% of the speed of serving files directly,
and uploads at the same speed (Linux, 1 GiB files over loopback without TLS:
~5800 against ~6100 MB/s; WEED_BENCH_MIB=1024 make bench-workers measures it). That
needs 4 MiB socket buffers, which root gets; as another user, also raise
net.core.wmem_max and net.core.rmem_max to 4194304, or downloads lose a third.

The users need search permission on the exported directory and its parents (and
weed, for /healthz). Accounts are looked up again after a minute, and on reload; an
account whose groups changed gets a new worker (the old one finishes its requests
first). On reload, workers re-read the CAs of TPC endpoints (tpc.ca_path), which the
users must be able to read; they keep running. SIGHUP sent to a worker is ignored.
Operations the filesystem refuses get 403. As with local tools:
* Replacing a file needs write permission on it as well as on its directory, and the
  new version belongs to the user who wrote it.
* Locking an existing resource needs write permission on it, so a user cannot lock
  others out of their files.
* WebDAV locks are kept by each worker: they only hold against requests of the same
  account, and are lost when its worker stops.

cgroups. With unix_users.cgroups, each worker runs in a cgroup of its own below
weed's, which must be delegated to weed (systemd's Delegate=yes; cgroup v2): weed
moves into <its cgroup>/main and starts the workers of alice in <its
cgroup>/worker-alice, with the cpu, io, memory and pids controllers when they are
available. systemd-cgtop and systemd-cgls then show what each account uses, and
unix_users.cgroup_limits writes limits into the cgroup of every worker:

    [unix_users]
    enabled = true
    cgroup_limits = ["memory.max=8G", "pids.max=1000", "cpu.weight=100"]

Without unix_users, weed warns at startup if it runs as root: every client would
have root's access to the files.


Reloading credentials

On SIGHUP, and every server.reload_interval (default 1h, "0s" disables), weed
re-reads the htpasswd and app tokens files, the grid-mapfile, the CAs and CRLs, the
token issuers, the TLS certificate, and the CAs for TPC endpoints (also in the worker
processes of unix_users) and token issuers, and looks Unix accounts up again. The
configuration file itself is only read at startup. A file that
cannot be read keeps its previous contents, so a file being rewritten neither locks
everybody out nor lets anybody in. New connections and requests use the new data.


Logging

weed logs with Go's log/slog to standard error, or to server.log_file, one record per
line: key=value text, or JSON with server.log_format = "json". server.log_level is
the least severe level logged (default "info"):

  error  what weed could not do, such as storing an upload, or a worker that failed
  warn   credentials it cannot reload, failed third-party copies, aborted uploads
  info   a "request" record per HTTP request, failed authentications and why,
         workers starting and stopping, third-party copies, credentials loaded
  debug  how each request was authenticated, uploads stored (with their adler32)

    time=2026-10-28T16:26:43.533+01:00 level=INFO msg=request method=PUT
      path=/webdav/hosts proto=HTTP/1.1 status=204 bytes=0 duration=12.60425ms
      user=alice remote=192.0.2.1:65278 user_agent=gfal2 request_id=c016524f

(one line in the log). Records logged while serving a request carry its request_id,
also when a worker process logs them: workers send their records to weed, which logs
them with worker.user and worker.pid. Values are quoted or escaped, so clients cannot
forge records with crafted paths or headers, and X-Forwarded-For is logged as
forwarded_for, never in place of the client's address. On SIGHUP weed reopens
server.log_file, so that logrotate can move it (postrotate: systemctl kill -s HUP
weed); under systemd, standard error goes to the journal.


Monitoring

/healthz, on the main port without authentication, answers 200 "ok", or 503 when
the exported directory cannot be stat'ed within 5 seconds (e.g. a hung network
filesystem).

server.metrics_address = "localhost:9100" serves, without authentication, /healthz and
Prometheus metrics on /metrics:
  weed_http_requests_total{method,code}       weed_http_response_bytes_total{method}
  weed_auth_requests_total{method,result}     weed_upload_bytes_total
  weed_checksum_mismatches_total{operation}   (put, tpc_pull, tpc_push)
  weed_tpc_transfers_total{mode,result}       weed_tpc_bytes_total{mode}
  weed_tpc_active_transfers{mode}             weed_tpc_rejected_total
  weed_reloads_total{result}                  weed_build_info{version,goversion}
  weed_workers                                weed_worker_starts_total{result}
  weed_worker_exits_total{reason}             (stopped when asked to, or failed)
  weed_crl_expiry_timestamp_seconds           when the first CA runs out of current
                                              CRLs (alert before it is reached)
  weed_tls_certificate_expiry_timestamp_seconds


Performance

Uploads and TPC transfers read the next 1 MiB while the previous one is written and
checksummed, and compute several digests in parallel, so checksums cost little more
than the slowest of network, disk and hashing. On an M1 Pro over loopback (2 GiB
files, MB/s): PUT or TPC pull with adler32 ~2450, + sha-256 ~1900, + md5 ~620 (md5
itself hashes at ~650); GET ~3000; the disk writes ~3800. Measure on your hardware:

    WEED_BENCH_MIB=4096 make bench


Testing

    make test          unit and end-to-end tests (go test -race ./...)
    make test-root     the same as root, adding the tests of unix_users worker
                       processes (Linux, uses sudo)
    make test-linux    the same as root in a Linux container, e.g. from macOS (Docker)
    make test-cgroups  the cgroups of worker processes, in a privileged container
    make interop       interoperability tests (test/interop/interop.sh, Docker)
    make check         gofmt and go vet; make fuzz, make cross, make vulncheck and
                       make bench run the rest; make help lists every target

The interoperability tests run weed in a container against real WLCG software:
gfal2, davix and curl as clients; XRootD (with its macaroons, SciTokens and HTTP-TPC
plugins) as a second implementation; and a test token issuer. They cover X.509
proxies, macaroons, tokens, revocation with SIGHUP, metrics, Unix accounts, and
third-party copies in both directions between two weed servers and between weed and
XRootD. Each parser also has a fuzz test (go test -fuzz). CI (.github/workflows/ci.yml)
runs the tests with -race on Linux and macOS and as root on Linux, go vet, gofmt,
govulncheck, cross-builds, the fuzz tests and the interoperability tests.


Not implemented

* X.509 credential delegation for TPC (Credential: gridsite): use tokens or
  macaroons in TransferHeaderAuthorization
* Authorization by token groups alone: a token needs storage scopes even when its
  groups choose its Unix account
* Per-user access without unix_users, or on systems other than Linux
* WebDAV locks across accounts with unix_users: each worker keeps its own


Known deviations from RFC 4918

WEED is meant for WLCG clients (gfal2, davix, FTS, XRootD), which are not affected by
these. Found with the litmus 0.13 WebDAV test suite, where basic, copymove and http
pass; props passes 10 of 14 tests and locks 30 of 34, failing only on the items below.

* If header: only lock tokens are evaluated, as in golang.org/x/net/webdav; entity
  tags and "Not" are ignored. On a locked resource, a write with its lock token
  succeeds even if the If header's entity tag does not match, and "(Not <token>)"
  counts as submitting the token; on an unlocked resource, any If header fails with
  412, even a matching entity tag. A write to a locked resource whose If header holds
  only a wrong token gets 412 rather than 423. The HTTP If-Match and If-None-Match
  headers work.
* Dead properties: PROPPATCH stores nothing; each property is refused with 403 in the
  207 response.
* Shared locks: LOCK with a shared scope gets 501; exclusive locks work.
* A PROPFIND body binding a prefix to the empty namespace (xmlns:p="") is accepted
  rather than refused with 400.
