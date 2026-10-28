WEED: WEbdav Exporter Daemon

WEED exports a local directory over WebDAV (RFC 4918) under /webdav/, and implements
WLCG HTTP third-party copy (pull and push) with the data-integrity extension described
in https://github.com/labkode/wlcg-tpc.

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

Remote endpoints must be https:// (unless -tpc-allow-http) and may not resolve to
loopback, link-local, multicast or unspecified addresses (unless -tpc-allow-local).
Redirects are followed (at most 10, never to http:// when that is not allowed, never
when they change the method). Use -tpc-ca-path /etc/grid-security/certificates to
trust IGTF CAs for remote endpoints.


Authentication

Methods are tried in this order; the first one that applies decides. A request that
presents bad credentials gets 401, or 403 if the credentials are valid but not allowed
to do what was asked. All authenticated users share the same namespace.

1. X.509 client certificates (-tls -x509-auth -ca-cert <file> -gridmap-file <file>)
   End-entity certificates and RFC 3820 (and legacy Globus) proxy chains are accepted.
   The DN, in OpenSSL format and certificate order (e.g.
   "/DC=ch/DC=cern/OU=Users/CN=jdoe"), is mapped to a user with the grid-mapfile.
   /proc/x509 shows how the server sees the presented certificate.

2. OIDC browser login (-oidc-auth -oidc-issuer ... -oidc-client-id ...
   -oidc-client-secret ... -oidc-redirect-url https://<host>/oidc_redirect)
   Start at /auth/oidc. The login is bound to the browser with a state cookie and a
   nonce; sessions last 24h.

3. Macaroons (-macaroon-auth -macaroon-secret-key <secret>)
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

4. HTTP Basic (-basic-auth -htpasswd-file <file> -app-tokens-file <file>)
   Passwords are checked against bcrypt entries in the htpasswd file, or against app
   tokens. Basic credentials are sent in clear text without -tls.

/proc/whoami shows the identity a request authenticates as.


Not implemented

* WLCG JWT / SciTokens bearer tokens
* X.509 credential delegation for TPC (Credential: gridsite)
* Certificate revocation (CRL) checks
* Per-user authorization
* Reloading credentials files without a restart (SIGHUP)
