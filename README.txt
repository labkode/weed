WEED: WEbdav Exporter Daemon

WEED exports a local directory over WebDAV (RFC 4918) under /webdav/, and implements
WLCG HTTP third-party copy (pull and push) with the data-integrity extension described
in https://github.com/labkode/wlcg-tpc. Clients authenticate with X.509 certificates
and proxies, WLCG/SciTokens bearer tokens, macaroons, OIDC or passwords.

Runs on Linux, macOS and Windows (checksum caching in extended attributes on Linux and
macOS only).

    go build && ./weed -dir /data -tls -basic-auth -macaroon-auth -macaroon-secret-key "$KEY"

Run ./weed -h for all flags. Helpers:

    ./weed utils password <user> <password>   add a bcrypt entry to .htpasswd
    ./weed utils token generate <user>        create an app token in .app-tokens


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


Third-party copy (enable with -tpc)

The server receiving the COPY is the active party: it performs the transfer itself and
answers 202 with a "text/perf-marker-stream" body. The body holds a performance marker
every -tpc-marker-interval and ends with "success: Created" or "failure: <reason>".
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
  Content-Encoding, or one that stalls for -tpc-stall-timeout, fails the copy.

Pre-flight errors (no transfer started): 400 bad Source/Destination or scheme, 404/405
push of a missing file or a collection, 405 pull onto a collection, 409 missing parent,
412 Overwrite: F onto an existing file, 423 target locked, 501 TPC disabled or
credential delegation requested (only "Credential: none" is supported), 503 too many
concurrent transfers (-tpc-max-transfers).

Remote endpoints must be https:// (unless -tpc-allow-http). So that a COPY cannot be
used to reach services inside the site, each address a remote resolves to is checked
when connecting (also after redirects):
* refused unless -tpc-allow-local: loopback, link-local, multicast, 0.0.0.0/8
* refused unless -tpc-allow-private: private (RFC 1918, fc00::/7), shared (100.64/10)
  and other special-purpose ranges (RFC 6890), and IPv6 forms embedding IPv4
  addresses (NAT64, 6to4, Teredo); IPv4-mapped IPv6 addresses count as IPv4
* always refused: the unspecified address
Redirects are followed (at most 10, never to http:// when that is not allowed, never
when they change the method). Use -tpc-ca-path /etc/grid-security/certificates to
trust IGTF CAs for remote endpoints.

With WLCG tokens, the client passes one token for weed (Authorization) and one for
the remote (TransferHeaderAuthorization); gfal2 does this with BEARER_TOKEN set.


Authentication

Methods are tried in this order; the first one that applies decides. A request that
presents bad credentials gets 401, or 403 if the credentials are valid but not allowed
to do what was asked. All authenticated users share the same namespace.

1. X.509 client certificates (-tls -x509-auth -ca-cert <path> -gridmap-file <file>)
   -ca-cert is a PEM file or a directory such as /etc/grid-security/certificates.
   End-entity certificates and RFC 3820 (and legacy Globus) proxy chains are accepted.
   The DN, in OpenSSL format and certificate order (e.g.
   "/DC=ch/DC=cern/OU=Users/CN=jdoe"), must be listed in the grid-mapfile, which
   maps it to a user: a certificate from a trusted CA whose DN is not listed gets 403,
   so trusting all of /etc/grid-security/certificates does not let in every grid user.
   With -x509-auth, weed does not start without a readable grid-mapfile; removing a DN
   from it and reloading revokes that user's access.
   /proc/x509 shows how the server sees the presented certificate.

   Proxy chains are refused when a proxy:
   * has a policy other than inherit-all or limited (e.g. independent),
   * is followed by more proxies than its path length allows,
   * is unrestricted but issued by a limited proxy,
   * is legacy and RFC 3820 in the same chain,
   * is expired or not yet valid, or its issuer lacks the digitalSignature key usage.
   Limited proxies are accepted (they are meant for data access).

   Revocation (-crl-path <path> [-crl-mode require|if-valid]): CRLs, PEM or DER, are
   read from a file or a directory such as /etc/grid-security/certificates, where
   fetch-crl keeps them (<hash>.r0). A certificate is checked against the newest
   current CRL signed by its issuer. With -crl-mode require (the default) a
   certificate whose issuer has no current CRL is refused, so an expired CRL fails
   closed; with if-valid, certificates are only checked against the CRLs that are
   present and current.

2. OIDC browser login (-oidc-auth -oidc-issuer ... -oidc-client-id ...
   -oidc-client-secret ... -oidc-redirect-url https://<host>/oidc_redirect)
   Start at /auth/oidc. The login is bound to the browser with a state cookie and a
   nonce; sessions last 24h.

3. WLCG and SciTokens bearer tokens (-token-issuers <file>)
   JWTs from the issuers listed in the file, as defined by the WLCG Common JWT
   Profiles (https://doi.org/10.5281/zenodo.3460258) and SciTokens:

    [{"issuer": "https://wlcg.cloud.cnaf.infn.it/",
      "audiences": ["https://weed.example:443"],
      "base_path": "/wlcg"}]

   The signature is checked against the keys the issuer publishes (found through
   /.well-known/openid-configuration, or oauth-authorization-server). Keys are cached,
   refetched every hour, and fetched at most once a minute per issuer, so forged
   tokens cannot make weed flood an issuer; if the issuer is down, the known keys keep
   working. Use -token-ca-path to trust CAs other than the system's for the issuers.
   A token must not be expired (1 minute of clock skew is allowed), and its aud must
   include one of the audiences or https://wlcg.cern.ch/jwt/v1/any; otherwise 401.

   Scopes grant access to a path and everything below it; paths are relative to the
   issuer's base_path (default "/"), which is relative to the exported directory:
     storage.read:<path>    read, list and stat (also storage.stage, SciTokens read)
     storage.create:<path>  create files and directories, rename, stat; never
                            replace or delete data: PUT, COPY/MOVE and TPC pull onto
                            an existing file get 403, before any data is sent
     storage.modify:<path>  also overwrite and delete (also SciTokens write)
   A scope without a path means "/". Tokens without storage scopes get 403: access
   based on groups (wlcg.groups) is not supported. A macaroon cannot be requested
   with a token, since it would not be bound by the token's scopes.

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

4. Macaroons (-macaroon-auth -macaroon-secret-key <secret>)
   Any authenticated user can mint a macaroon for a path by POSTing to that path:

    curl -u user:pass -X POST https://weed.example/webdav/dir_0/dir_1/ \
        -H 'Content-Type: application/macaroon-request' \
        -d '{"caveats": ["activity:DOWNLOAD,LIST"], "validity": "PT1H"}'
    => {"macaroon": "<token>", "expires_in": 3600}

   Use it with "Authorization: Bearer <token>". The token is valid only for that path
   and below, and always expires: validity defaults to and is capped at
   -macaroon-max-validity (24h). Minting with a macaroon yields an attenuated copy that
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

5. HTTP Basic (-basic-auth -htpasswd-file <file> -app-tokens-file <file>)
   Passwords are checked against bcrypt entries in the htpasswd file, or against app
   tokens. Basic credentials are sent in clear text without -tls.

/proc/whoami shows the identity a request authenticates as.


Reloading credentials

On SIGHUP, and every -reload-interval (default 1h, 0 disables), weed re-reads the
htpasswd and app tokens files, the grid-mapfile, the CAs and CRLs, the token issuers,
the TLS certificate, and the CAs for TPC endpoints and token issuers. A file that
cannot be read keeps its previous contents, so a file being rewritten neither locks
everybody out nor lets anybody in. New connections and requests use the new data.


Monitoring

/healthz, on the main port without authentication, answers 200 "ok", or 503 when
the exported directory cannot be stat'ed within 5 seconds (e.g. a hung network
filesystem).

-metrics-address localhost:9100 serves, without authentication, /healthz and
Prometheus metrics on /metrics:
  weed_http_requests_total{method,code}       weed_http_response_bytes_total{method}
  weed_auth_requests_total{method,result}     weed_upload_bytes_total
  weed_checksum_mismatches_total{operation}   (put, tpc_pull, tpc_push)
  weed_tpc_transfers_total{mode,result}       weed_tpc_bytes_total{mode}
  weed_tpc_active_transfers{mode}             weed_tpc_rejected_total
  weed_reloads_total{result}                  weed_build_info{version,goversion}
  weed_crl_expiry_timestamp_seconds           when the first CA runs out of current
                                              CRLs (alert before it is reached)
  weed_tls_certificate_expiry_timestamp_seconds


Performance

Uploads and TPC transfers read the next 1 MiB while the previous one is written and
checksummed, and compute several digests in parallel, so checksums cost little more
than the slowest of network, disk and hashing. On an M1 Pro over loopback (2 GiB
files, MB/s): PUT or TPC pull with adler32 ~2450, + sha-256 ~1900, + md5 ~620 (md5
itself hashes at ~650); GET ~3000; the disk writes ~3800. Measure on your hardware:

    WEED_BENCH_MIB=4096 go test ./internal/server -run '^$' -bench . -benchtime 3x
    go test ./internal/digest -run '^$' -bench Hasher


Testing

    go test -race ./...           unit and end-to-end tests
    test/interop/interop.sh       interoperability tests, needs Docker

The interoperability tests run weed in a container against real WLCG software:
gfal2, davix and curl as clients; XRootD (with its macaroons, SciTokens and HTTP-TPC
plugins) as a second implementation; and a test token issuer. They cover X.509
proxies, macaroons, tokens, revocation with SIGHUP, metrics, and third-party copies
in both directions between two weed servers and between weed and XRootD. Each
parser also has a fuzz test (go test -fuzz). CI (.github/workflows/ci.yml) runs the
tests with -race on Linux and macOS, go vet, gofmt, govulncheck, cross-builds, the
fuzz tests and the interoperability tests.


Not implemented

* X.509 credential delegation for TPC (Credential: gridsite): use tokens or
  macaroons in TransferHeaderAuthorization
* Per-user authorization: all authenticated users share the same namespace (tokens
  and macaroons can be restricted to paths); group-based token authorization


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
