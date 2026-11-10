WEED: WEbdav Exporter Daemon

WEED exports a local directory over WebDAV (RFC 4918) under /webdav/, and implements
WLCG HTTP third-party copy (pull and push) with the data-integrity extension described
in https://github.com/labkode/wlcg-tpc. Clients authenticate with X.509 certificates
and proxies, WLCG/SciTokens bearer tokens (which browsers can get from an OIDC login
page), macaroons or passwords.

Every request accesses files as the Unix account that its credentials map to, from a
worker process running as that account (see Unix accounts), so weed serves on Linux,
as root or as an account of its own with CAP_SETUID, CAP_SETGID and CAP_KILL, and
keeps none of it once started. It targets AlmaLinux 10 (EL10), which its tests run
on; weed and its helpers (weed utils) build and run on Linux alone. weed does not
need systemd: any supervisor runs it, SIGHUP reloads it, SIGTERM stops it (see the
guide's Installation, Without systemd). Releases, on
https://github.com/labkode/weed/releases, have weed for linux/amd64 and linux/arm64,
an RPM for EL10 that installs it as a systemd service running as the account weed
(packaging/), and CHANGELOG.md what each version changed, incompatible changes first
(see Releases).

    go build && sudo ./weed

serves the current directory at http://127.0.0.1:9000/webdav/ to local clients,
without authentication, as the account nobody (so they can read and write what nobody
can), with its metrics, status and dashboard at http://127.0.0.1:9000/metrics,
/status and /dashboard/. Anything else is set in a configuration file:

    ./weed config >weed.toml     every option, its default and what it does
    ./weed check -config weed.toml   would weed start with it? (see What runs)
    ./weed -config weed.toml
    ./weed version
    sudo ./weed limits -config weed.toml   what can weed serve here? (see Tuning)

Helpers:

    ./weed utils password <user>          set a password, asking for it (-delete removes)
    ./weed utils token generate <user>    create an app token
    (in the files of basic.htpasswd and basic.app_tokens of /etc/weed/weed.toml,
    -config's, or -file; .htpasswd and .app-tokens here without any)

The administration guide, docs/html/index.html, explains how to install, set up and
run weed, with every option, metric and command. Its pages are written in Markdown in
docs/src, and made into docs/html by pandoc: "make docs" after changing them.


Configuration

A TOML file, in which every option is optional, for example:

    [server]
    port = 443
    dir = "/data"
    metrics_address = "localhost:9180"

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

The sections are server, tls, x509, basic, oidc, macaroons, tokens, tpc, unix_users
and admin; below, section.key names an option (e.g. tpc.max_transfers). Unknown
sections and keys are errors, so a misspelt option stops weed instead of being
ignored. Durations are strings such as "90s", "10m" or "24h". weed refuses to read a
file that holds secrets (macaroons.secret_key, oidc.client_secret) if every user can
read it. Changes to the file take effect on restart.

server.anonymous serves requests without credentials as the Unix account nobody. It
is the default without a configuration file, and weed only allows it when
server.address is a loopback address, so only local clients (any local user) reach
it. Credentials that an enabled method rejects still get 401.


Storage guarantees

* Uploads (PUT, local COPY, TPC pull) are written to a hidden temporary file in the
  target directory, fsynced, and renamed into place only once complete and verified.
  An interrupted or failed upload never replaces or truncates an existing file.
  Temporary files (".weed-upload-*") are invisible to WebDAV clients.
* LOCKs are honoured by every write, including PUT and TPC pull.
* MOVE overwrites by default, as RFC 4918 requires; COPY or MOVE of a collection onto
  itself or into one of its descendants is refused (403).
* PROPFIND with Depth: infinity (or no Depth) is refused (403). PROPFIND opens no
  file: its properties come from metadata.
* A file's content type (GET's Content-Type, PROPFIND's getcontenttype) comes from
  its name's extension, by the system's MIME types and Go's, and is
  application/octet-stream otherwise; weed does not read files to guess it.
* Paths with encoded dot segments ("%2e%2e") are refused.


Checksums (RFC 9530 Repr-Digest, and legacy RFC 3230 Digest)

Supported algorithms: adler (alias adler32), crc32c, md5, sha, sha-256, sha-512.
Checksums are computed only while weed writes a file (PUT, TPC pull): adler32
always, and those the client sent. They are stored in extended attributes
(user.weed.digest.<alg>), and are no longer valid once the file's size or mtime
changes. Reads never compute one: a file that weed did not write has none.

PUT with a Repr-Digest header, e.g. "adler=:AAAAAQ==:, md5=:1B2M2Y8AsgTpgAmY7PhCfg==:"

CONDITION                                                  HTTP CODE
* header absent                                         => upload is not verified
* header malformed                                      => 400 (Bad Request)
* header empty, or none of its algorithms is supported  => 406 (Not Acceptable)
* a supported digest differs from the received data     => 412 (Precondition Failed)
                                                           and the file is not stored
* all supported digests match                           => 201 / 204, with Repr-Digest

GET and HEAD return Repr-Digest when asked with Want-Repr-Digest (e.g. "adler=9"),
and Digest when asked with the legacy Want-Digest (e.g. "adler32"): the most
preferred of the stored checksums, or none.

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
to do what was asked. Every identity has a username, which must be a local account,
as which the request then accesses files (see Unix accounts below).

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


Unix accounts

Every identity must be the name of a local account, looked up with the system's user
database (/etc/passwd, or LDAP and SSSD through NSS when weed is built with cgo); an
identity without one, or that names root, gets 403, and anonymous requests are the
account nobody's. weed itself never touches the exported files: it terminates TLS,
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
they are all busy, requests of other accounts get 503. Each worker serves at most
unix_users.max_requests (default 4000) requests at once; beyond, its account's
requests get 503 (see "Storage that does not answer" below). Of those, at most
unix_users.max_storage_calls (default 256) call the storage at once (an open, a stat,
a batch of a listing, one read or write): each call holds a thread until the storage
answers, and the requests beyond wait for one to end without a thread, until their
clients go. A worker thus has no more threads than that, plus one per CPU and the
few tens of Go's, however many requests it serves. Workers log through weed,
their records marked worker.user=alice worker.pid=1630 (see Logging). Each worker
checks that all its threads run as the account, with no capabilities and
no_new_privs, and refuses to serve otherwise; weed starts one as nobody (65534) at
startup to find problems before the first request. Workers get none of weed's
environment.

Workers always run the same build as weed. They are started from /proc/self/exe,
weed's own binary even after an upgrade has replaced it on disk, so a new version
only runs once weed is restarted (until then, weed reports a restart pending, see What
runs, and ls -l /proc/<pid>/exe shows the old binary as deleted, for weed and its
workers alike). Each worker also reports the Go
build ID of its binary, which the linker derives from its content, and weed refuses
workers whose build is not its own: if the binary is overwritten in place, new
workers are refused (logged as "cannot start a worker", with both builds; requests
get 503) until weed is restarted. The binary must be readable and executable by the
users, as it normally is (0755).

weed talks HTTP to its workers over socket pairs: nothing else can connect to them,
so they trust the identity weed states in request headers (headers of the same names
sent by clients are dropped). They report their metrics back to weed, which serves
them; tpc.max_transfers bounds the copies of all accounts together.

Starting workers as other accounts needs root, or the capabilities CAP_SETUID and
CAP_SETGID, and stopping them CAP_KILL; weed does not start without them ("weed must
run as root, or with the capabilities ..."). The RPM's unit, packaging/weed.service,
runs weed as the account weed with them:

    User=weed
    AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_KILL CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_NET_BIND_SERVICE
    # for unix_users.cgroups
    Delegate=yes
    # admin.socket, admin.bans and server.log_file
    RuntimeDirectory=weed
    StateDirectory=weed
    LogsDirectory=weed

weed keeps none of them (internal/worker/starter_linux.go). Before it reads a
request, it starts its starter of workers, "weed starter" with weed's arguments, over
a socket pair, from a thread that keeps CAP_SETUID, CAP_SETGID and CAP_KILL alone,
with no_new_privs, and seccomp's filter of the workers. Then weed gives up its
capabilities (but CAP_NET_BIND_SERVICE, for a port below 1024) and confines itself.
The starter reads the configuration itself, and checks that its SHA-256 is weed's. It
starts and kills the workers that weed asks for, messages of JSON with the worker's
two sockets as SCM_RIGHTS: it looks the account up itself, and refuses root, and an
account other than weed has it. It sends weed its log, and when the exported
directory changes. It is not confined with Landlock, which it applies to each worker,
so that it reaches the exported directory as storage comes and goes. If it exits,
weed exits with status 1, and systemd starts both again.

Downloads relayed from workers run at ~92% of the speed of serving files directly,
and uploads at the same speed (Linux, 1 GiB files over loopback without TLS:
~5200 against ~5600 MB/s; WEED_BENCH_MIB=1024 make bench-workers measures it). That
needs 1 MiB socket buffers: raise net.core.wmem_max and net.core.rmem_max to 1048576
(the RPM's packaging/weed.sysctl does), or downloads lose a third; weed, as root too,
has not the CAP_NET_ADMIN that exceeds them.
Larger buffers would gain a few percent of one stream, but a client that reads
slower than its worker keeps them full: 4 MiB took 7 MB of memory per slow client,
1 MiB takes 2.7 MB (test/stress, slow-download).

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

What workers reach. Beyond the permissions of its account, two things keep a worker
to the exported directory:
* Symbolic links: workers open every name beneath the exported directory with
  openat2(2), and follow no symbolic link, wherever it is in the name and wherever
  it points. A name with a link in it gets 403 and is logged ("refused a name with a
  symbolic link in it"), and links are left out of listings. Otherwise, a user who
  can make links there (over ssh, NFS) could have weed read whatever the account
  can, such as /etc, and a link in a directory would take a token or macaroon for
  that directory wherever it points. Bind-mount a directory to serve it from
  elsewhere.
* Landlock (Linux 5.19 or later, with landlock among the security modules, lsm=):
  weed confines itself and each worker as it starts it, and does not start without
  it. Whatever a bug in a worker tries, it may write beneath the exported directory
  alone, and read only beneath it and /etc, /usr, /lib, /proc and /sys/fs/cgroup (and
  tpc.ca_path, SSL_CERT_FILE and SSL_CERT_DIR), whatever the permissions: not /home,
  /tmp, nor files of other services. It may execute weed alone (and, for a build with
  cgo, its dynamic loader, which can run other programs, confined the same); it cannot
  make symbolic links, devices, sockets or FIFOs; from Linux 6.7, it binds no TCP port,
  and connects to none unless tpc.enabled, for third-party copies (Landlock does not
  confine UDP, nor MPTCP: see seccomp below); from Linux 6.12, it signals no process
  (but on RHEL 9's kernels, which lack that) and connects to no abstract Unix socket
  outside its confinement. weed logs the rules as it starts ("workers are confined with
  Landlock"). Each worker checks that it is confined, and refuses to serve otherwise.
  On some file systems, such as Docker Desktop's mounts of the host, Landlock refuses
  every access whatever its rules: weed then does not start, and says so, if the
  exported directory or weed's binary is on one. Landlock does not cover stat, chmod,
  chown, utime and extended attributes: on files outside the exported directory,
  permissions alone keep those.
* seccomp: Landlock's rules of TCP cover TCP alone, not MPTCP, which Go listens with
  where the kernel has it and which falls back to TCP with peers that do not, nor
  SCTP, SMC, raw or packet sockets. weed filters the system calls of itself and of
  each worker: a worker opens Unix sockets alone, and with tpc.enabled TCP and UDP
  ones too (UDP to resolve names); weed's own process opens Unix, netlink, TCP and UDP
  sockets. Neither has io_uring, which opens sockets without socket(2). weed logs
  them (sockets=), and refuses to start if it is not filtered; each worker checks
  that it is, and refuses to serve otherwise. The filters are of amd64 and arm64.
And weed's own process, which terminates TLS and authenticates requests, without
capabilities: it may write the directories of server.log_file, admin.socket and
admin.bans, and read only those, the system's files (as workers) and the files that
its configuration names, not the exported directory; from Linux 6.7, it binds only its ports,
and connects only to token issuers and for third-party copies. Landlock confines a
thread and what it executes, so weed executes itself again, from a thread that it
confines; it logs the rules as it does ("weed confines itself with Landlock"), and
refuses to start if it then is not confined, or has capabilities. Confined to /,
weed would reach everything: it does not export /. Landlock confines to plain
directories and to mount points alike: a rule names the directory that its path leads
to as a worker starts (the root of the storage mounted at /data, or the plain
directory /data), and covers what is beneath, storage mounted below it later
included; not a storage mounted over it or above it later (a remount), nor the
directory beneath a storage that is unmounted. The starter looks at the directory
every 5 seconds. When a storage is there in its place, weed retires the workers
confined to the directory as it was, which finish their requests, and the next
requests get workers confined to the storage. When the storage that the directory was
on, at startup or mounted since, is no longer mounted, weed does not exit: it refuses requests (503, /healthz too, the metric
weed_storage_unmounted is 1) until the storage is back, never serving the directory
beneath, which would take the uploads. A weed that starts while the storage is not
mounted would serve it: with server.require_mount, weed does not start while the
exported directory is on the file system of /.
Two more are not part of weed:
* A mount namespace per worker, holding only the exported directory and the system
  files a worker needs (pivot_root, as containers do): what is outside does not
  exist for it, not even for stat. weed would need CAP_SYS_ADMIN, and storage
  mounted after a worker started (autofs, NFS remounts) to propagate into it.
* systemd's sandboxing confines weed and its workers together, as Landlock does weed's
  own process, and with directives that Landlock does not have: for instance
  ProtectSystem=strict (all read-only, but /dev, /proc, /sys and the directories of
  RuntimeDirectory=weed, StateDirectory=weed and LogsDirectory=weed, which
  admin.socket, admin.bans and server.log_file need), ReadWritePaths=/data (the
  exported directory),
  ProtectHome=yes (unless the exported directory is below /home), PrivateTmp=yes.
  The RPM's unit has ProtectSystem=full and the directives that need no path (see
  the guide's Installation, Sandboxing). It does not separate the accounts from each
  other. make test-systemd runs weed with these directives (see Testing); try others
  with weed check and a few requests of each kind.

cgroups. With unix_users.cgroups, the workers of each account run in a cgroup of
their own below weed's, which must be delegated to weed (systemd's Delegate=yes;
cgroup v2): the starter moves itself and weed into <its cgroup>/main and starts the
workers of alice in <its cgroup>/worker-alice, with the cpu, io, memory and pids controllers when they are
available. systemd-cgtop and systemd-cgls then show what each account uses, and
unix_users.cgroup_limits writes limits into the cgroup of every account:

    [unix_users]
    cgroup_limits = ["memory.max=8G", "pids.max=5000", "cpu.weight=100"]

pids.max counts threads, and a worker that cannot make one dies: keep it above
unix_users.max_storage_calls, plus the CPUs, plus a hundred. The Go runtime of a worker keeps below 90% of the lower of
its cgroup's memory.max and memory.high (GOMEMLIMIT prevails), which it reads when it
starts and when weed reloads.

Limits per user and group. unix_users.limits names a JSON file of rules, which weed
reads at startup (it does not start if it cannot) and on every reload (one that
cannot be read keeps the previous rules, and the reload is partial):

    [{"group": "cms", "cgroup_limits": ["memory.max=32G", "cpu.weight=300"]},
     {"user": "alice", "cgroup_limits": ["io.max=8:16 rbps=200000000"]}]

Each cgroup limit of an account comes from the first rule for the user that sets its
file, else from the first for one of its groups, else from unix_users.cgroup_limits.
A reload writes them into the cgroups of the accounts that have workers; a limit no
longer configured stays until they have all exited (weed says so: set it to its
unlimited value, e.g. memory.max=max).

Network rates. weed does not pace transfers: the kernel does. tc on the network
interface limits what the machine sends, in total (htb, tbf) or per connection (fq's
maxrate), and with a policer or an ifb device what it receives; io.max in the cgroup
of each account (above) limits what its workers read and write of a block device.
The clients' transfers flow through weed's own process: the network cannot tell their
accounts apart.

Storage that does not answer. A request whose file system does not answer (a hung NFS
server, a failing disk) waits in the kernel with one of its worker's threads, which
nothing interrupts, not even SIGKILL, and which the request keeps after its client
has gone. The worker's other requests go on, as long as fewer than
unix_users.max_storage_calls of its calls are stuck: beyond, all of them wait, without
a thread, until a call returns or their clients go. Other accounts' workers go on; weed
itself never touches the files, but /healthz, which makes one stat of the exported
directory at a time, and the look of Landlock at it every 5 seconds (from one
goroutine, with what the kernel has cached): until it has first answered, requests
that would start a worker get 503. So that stuck threads cannot pile up until the
Go runtime stops the worker (at 10000), a worker has at most
unix_users.max_storage_calls of them; it counts its requests until it has finished
them, and refuses those beyond unix_users.max_requests with 503; an idle
worker with stuck threads is kept rather than replaced by a new one, which could get
stuck too. /status (blocked_threads of each worker) and weed_worker_blocked_threads
count the threads waiting in the kernel. A worker killed meanwhile, by a ban or as
weed stops, exits only once its threads return: weed waits 10 seconds for it, then
says so (weed utils ban exits with 1) and goes on.


Reloading credentials

On SIGHUP, and every server.reload_interval (default 1h, "0s" disables), weed
re-reads the htpasswd and app tokens files, the grid-mapfile, the CAs and CRLs, the
token issuers, the TLS certificate, the CAs for TPC endpoints (also in the worker
processes) and token issuers, and the limits file (unix_users.limits), and looks
Unix accounts up again. A file
that cannot be read keeps its previous contents, so a file being rewritten neither
locks everybody out nor lets anybody in. New connections and requests use the new
data. The configuration file itself is only read at startup: weed says when it has
changed (see What runs).


Banning users

    # weed utils ban -reason "compromised credentials" alice
    banned alice; stopped its 1 worker process(es)
    # weed utils bans
    USER   SINCE                    BY                REASON
    alice  2026-10-29 01:12:03 CET  uid 0, pid 51234  compromised credentials
    # weed utils unban alice
    lifted the ban of alice

weed refuses the requests of a banned user with 403, whatever their credentials. The
user is the Unix account that they map to, as the request records log it (nobody:
anonymous requests). A ban takes effect at once: weed kills the user's worker
processes, aborting its requests in progress (an upload never replaces a file unless
complete), and starts none for it until the ban is lifted; nor does the OIDC login
give the user tokens. Refused requests are logged as "authentication failed", with
the ban; bans as "user banned" and "ban lifted", with who did it (the uid and pid of
weed utils). weed_banned_users and /status count the banned users.

Bans are kept in admin.bans (default /var/lib/weed/bans.json), which weed writes on
every change and reads at startup. If it cannot write it, weed utils says so and
exits with 1: the change lasts until weed stops.

weed utils talks to the running weed through its control plane, an HTTP API with JSON
bodies on the Unix socket admin.socket (default /run/weed/admin.sock, "" disables
it), which only root and the user weed runs as can use: the socket is 0600 in a
directory that only its owner may enter, and weed checks who connects (SO_PEERCRED).
weed utils finds the socket with -config (the file weed runs with) or -socket,
otherwise it uses the default. A weed does not start while another listens on its
socket, and replaces one left by a weed that died. The API is versioned, so that
operations can be added:

    GET    /v1/bans         -> {"bans": [{"user", "since", "reason", "by"}, ...]}
    PUT    /v1/bans/{user}  {"reason": "..."} -> the ban, "added", "workers_killed"
    DELETE /v1/bans/{user}  -> {"user", "removed"}

Errors are {"error": "..."}, with a status other than 2xx; a weed that does not have
an operation answers 404.


Logging

weed logs with Go's log/slog to standard error, or to server.log_file, one record per
line: key=value text, or JSON with server.log_format = "json". server.log_level is
the least severe level logged (default "info"):

  error  what weed could not do, such as storing an upload, or a worker that failed
  warn   credentials it cannot reload, failed third-party copies, aborted uploads, bans
  info   a "request" record per HTTP request, failed authentications and why,
         workers starting and stopping, third-party copies, credentials loaded
  debug  how each request was authenticated, uploads stored (with their adler32)

    time=2026-10-28T16:26:43.533+01:00 level=INFO msg=request method=PUT
      path=/webdav/hosts proto=HTTP/1.1 status=204 bytes=0 duration=12.60425ms
      user=alice remote=192.0.2.1:65278 user_agent=gfal2 request_id=c016524f

(one line in the log). Every request to the main port gets one, and is counted in
weed_http_requests_total, whatever it is for: /webdav/, /healthz, the index page,
unknown paths. Requests to server.metrics_address (Prometheus scrapes) get neither.
user is the Unix account that the request's credentials map to (the grid-mapfile's,
an issuer's user rule's, the one a macaroon was minted for, the htpasswd entry), also
when they do not allow the request (403). It is nobody when no credentials map to
anyone: anonymous requests, invalid or expired credentials, and routes that take
none, such as /healthz.
Records logged while serving a request carry its request_id, also when a worker
process logs them: workers send their records to weed, which logs them with
worker.user and worker.pid. Values are quoted or escaped, so clients cannot forge
records with crafted paths or headers, and X-Forwarded-For is logged as
forwarded_for, never in place of the client's address. On SIGHUP weed reopens
server.log_file, so that logrotate can move it (the RPM installs
/etc/logrotate.d/weed, whose postrotate is systemctl reload weed); under systemd, standard error goes to the journal. Log to a file to keep every
record: the journal keeps so many lines of a service every 30 seconds (10000 by
default) and drops the others until the 30 seconds are over, weed's errors with its
requests, so a server answering more than a few hundred requests a second loses
records there. With server.log_file = "/var/log/weed/weed.log" and LogsDirectory=weed
in the unit, the file keeps them all, some 270 bytes a request (23 GB a day at 1000
requests a second); writing them costs weed some 4% of its requests at 60000 a
second.


Monitoring

/healthz, on the main port without authentication, answers 200 "ok", or 503 when
the exported directory cannot be stat'ed within 5 seconds (e.g. a hung network
filesystem). It makes one stat at a time: while one hangs, calls wait for it.

server.metrics_address = "localhost:9180" serves, without authentication, /healthz,
/status (see What runs), Prometheus metrics on /metrics, and a dashboard of both at
http://localhost:9180/: the browser reads them every 2 seconds and shows throughput,
requests, accounts and workers, with the last 10 minutes as charts. The
dashboard only reads. Without a configuration file, the main port serves them all
(the dashboard at /dashboard/): its clients are local, and can already read and write
every file. The metrics:
  weed_http_requests_total{method,code}       weed_http_response_bytes_total{method}
  weed_auth_requests_total{method,result}     weed_upload_bytes_total
  weed_checksum_mismatches_total{operation}   (put, tpc_pull, tpc_push)
  weed_tpc_transfers_total{mode,result}       weed_tpc_bytes_total{mode}
  weed_tpc_active_transfers{mode}             weed_tpc_rejected_total
  weed_reloads_total{result}                  (success, partial)
  weed_workers                                weed_worker_starts_total{result}
  weed_worker_exits_total{reason}             (stopped when asked to, killed by a
                                              ban, or failed)
  weed_worker_blocked_threads                 threads of the workers waiting in the
                                              kernel (for long: storage that does
                                              not answer)
  weed_banned_users
  weed_crl_expiry_timestamp_seconds           when the first CA runs out of current
                                              CRLs (alert before it is reached)
  weed_tls_certificate_expiry_timestamp_seconds
  weed_requests_in_progress{kind}             (download, upload, tpc_pull, tpc_push,
                                              other)
and what runs (see What runs).

weed_requests_in_progress counts the authenticated WebDAV requests being served now:
downloads (GET), uploads (PUT), third-party copies (COPY with Source: tpc_pull; to
another server's Destination: tpc_push), and the others (PROPFIND, MKCOL, DELETE,
MOVE, local COPY, ...). weed counts them for all accounts together, as it hands them
to the workers; /status also counts them by user (see What runs). A copy counts for
as long as its COPY request lasts: also while weed checks it, before
weed_tpc_active_transfers counts it.


What runs

So that nothing changes by surprise at runtime, weed says which build runs, since
when, with which configuration, and whether a restart would change any of it.

    $ weed version
    weed v1.2.0
    commit   46a37813bc81d7a1b9a8b1e2a9e1f3c3e6c2a0d4 (2026-10-28T16:07:11Z)
    go       go1.27.3 linux/amd64
    build    go:2CX-x4_-THjPR2Dy4JCE/TtMef8lUxfkIJsGhiXwh/3-NbDYhNvYZpdojQpjfp/Dg3...

The version is that of the module: a release tag, or v0.0.0-<time>-<commit> for other
commits, with +dirty (and "with uncommitted changes") if the tree had changes; built
without VCS information (go build -buildvcs=false, or outside a git checkout) it is
"(devel)". The build is the Go build ID, which the linker derives from the binary's
content: two binaries with the same build are the same.

At startup, weed logs a "starting weed" record with the version, commit, build, pid
and executable, and a "configuration" record with the configuration file, the SHA-256
of its content and the value of every option, defaults included (secrets are
"<redacted>" when set):

    level=INFO msg=configuration file=/etc/weed/weed.toml sha256=b78bbdeed036...
      config.server.address="" config.server.port=443 config.server.dir=/data ...

Restart pending. The configuration file is only read at startup, and a new binary
only runs once weed restarts. Every minute, on SIGHUP and on reloads, and when
/metrics or /status is read, weed looks at both. If the file now sets other values,
it logs a warning naming them; if weed would not start with the file (a syntax error,
an unknown option, a file that is gone), an error, now rather than at the next
restart. Changes to comments and layout only are not reported. If the binary has
been replaced by another build, weed logs the new one's version, read from the file
without running it:

    level=WARN msg="restart pending: the configuration file has changed:
      server.port, tpc.enabled" reason=config
    level=ERROR msg="restart pending: the configuration file has changed, and weed
      would not start with it: ..." reason=config
    level=WARN msg="restart pending: weed's executable /usr/local/bin/weed is now
      v1.3.0 (commit 9c1e0a2b77d4 of ...) go1.27.3 linux/amd64, build go:..."
      reason=binary

(one line each in the log).
Each is logged once, and "restart no longer pending" once the change is undone.

weed check -config weed.toml does what starting does, without serving: it reads the
configuration and every file it names (credential files, the certificate and its
key, CAs, CRLs, token issuers), contacts the OIDC provider, and starts
a worker as nobody (without setting cgroups up, which would change the cgroup it runs
in). It prints the warnings weed would log, and the SHA-256 of the file; if weed
would not start, it says why and exits with 1. It does not try to listen on the
configured addresses, which are in use while weed runs. Run it before restarting
weed, or let systemd do so. Run by root, it checks again as the account that weed
runs as (-as, or User= of weed.service), with the unit's capabilities, as root reads
files that the account may not; -as root checks as root alone. The RPM runs it on
upgrade, as the new version, and dnf shows how it went.

systemd. weed is a Type=notify service: it tells systemd that it is ready once it
listens (so systemctl start fails when weed cannot start, and units ordered after
weed start once it serves), when it reloads, and when it stops, and keeps a status
line up to date:

    [Service]
    # systemd >= 253; before, Type=notify and ExecReload=kill -HUP $MAINPID
    Type=notify-reload
    ExecStartPre=/usr/bin/weed check -config /etc/weed/weed.toml
    ExecStart=/usr/bin/weed -config /etc/weed/weed.toml
    # after a crash, up to a minute apart, for ever (StartLimitIntervalSec=0)
    Restart=on-failure
    # a worker killed for memory does not stop weed
    OOMPolicy=continue
    # weed bounds its threads itself (see Performance)
    TasksMax=infinity

packaging/weed.service is the whole unit, which the guide's Installation shows (make
test-systemd checks that they are the same).

    $ systemctl status weed
    ...
     Status: "Serving since 2026-10-28 16:07:11 UTC: weed v1.2.0, /etc/weed/weed.toml
              (sha256 b78bbdeed036); restart pending: the configuration file has
              changed: server.port"

With Type=notify-reload, systemctl reload weed sends SIGHUP and returns once the
reload is done. Worker processes cannot notify systemd. With a socket unit
(weed.socket: ListenStream=443 and that of server.metrics_address), systemd listens on
weed's ports and passes the sockets (LISTEN_FDS): while weed restarts, clients wait in
the queue instead of being refused, and weed binds no port; it takes each socket by
its port, and listens itself on the others. Out of memory, the kernel kills within
the cgroup of an account that reaches its memory.max (unix_users.cgroup_limits), not
weed's own process. weed's oom_score_adj is that of its workers: confined with
Landlock, neither may write /proc.

Metrics, on server.metrics_address:
  process_start_time_seconds
  weed_build_info{version,revision,modified,goversion,build}
  weed_config_info{file,sha256}
  weed_restart_pending{reason}               1 if the configuration file (config)
                                             or the executable (binary) has changed
  weed_reload_last_success_timestamp_seconds the last complete reload, or startup
  weed_reload_last_successful                0 if the last reload could not read
                                             a file, which kept its contents
For example, alert on weed_restart_pending == 1 for a day, on
weed_reload_last_successful == 0, and on count(count by (build) (weed_build_info)) > 1
across servers that should run the same build.

/status, also on server.metrics_address, tells all of it as JSON:

    {
      "version": {"version": "v1.2.0", "revision": "46a37813...",
        "time": "2026-10-28T16:07:11Z", "modified": false, "go": "go1.27.3",
        "platform": "linux/amd64", "build": "go:..."},
      "pid": 4242, "started": "2026-10-28T16:07:11.52Z", "uptime": "3h2m1s",
      "config": {"file": "/etc/weed/weed.toml", "sha256": "b78bbdeed036...",
        "settings": {"server": {"port": 443, ...},
                     "macaroons": {"secret_key": "<redacted>", ...}, ...}},
      "reload": {"last": "2026-10-28T18:07:11.6Z",
        "last_success": "2026-10-28T18:07:11.6Z", "successful": true},
      "restart_pending": {"config": "the configuration file has changed: server.port"},
      "workers": [{"account": "alice", "uid": 1001, "pid": 4250, "started": "...",
        "requests": 1, "retired": false}],
      "banned_users": 0,
      "in_progress": {"total": {"download": 2, "upload": 1, "tpc_pull": 0,
          "tpc_push": 1, "other": 0},
        "by_user": {"alice": {"download": 1, "tpc_push": 1},
                    "cms001": {"download": 1, "upload": 1}}}
    }

sha256sum /etc/weed/weed.toml tells whether the file is still the one weed runs with.
workers lists the worker processes; a retired one finishes its requests
and takes no new ones (its account's groups changed). in_progress counts the requests
being served (see weed_requests_in_progress in Monitoring): in total, by kind, and for
each user that has some, by the kinds it has.


Performance

Uploads and TPC transfers read the next 1 MiB while the previous one is written and
checksummed, and compute several digests in parallel, so checksums cost little more
than the slowest of network, disk and hashing. On an M1 Pro over loopback (2 GiB
files, MB/s): PUT or TPC pull with adler32 ~2450, + sha-256 ~1900, + md5 ~620 (md5
itself hashes at ~650); GET ~3000; the disk writes ~3800. Measure on your hardware:

    WEED_BENCH_MIB=4096 make bench

Clients that hold a connection cost little: 8192 clients each making a GET of a 4 KiB
file every second got 8172 requests/s, p99 35 ms, from weed using 2.7 CPUs and 1.6 GB
(196 kB per client; one account, through TLS, in a container of 8 CPUs and 8 GB). A
download that its client reads slower than weed sends, as across a WAN, holds about
2.7 MB in the kernel and in weed. Each connection is an open file: Go raises weed's
soft limit to the hard one (524288 under systemd). test/stress measures a server (see
Testing).

What limits what, on a laptop of 12 cores (24 threads) with an NVMe SSD (btrfs),
weed serving one account through TLS to a client certificate, and test/stress on the
same machine over loopback:
  PROPFIND Depth 1    24800/s of 100 entries, 5100/s of 1000, 560/s of 10000: the
                      CPUs, ~2 µs an entry in the worker
  GET of 4 KiB        60500/s: the CPUs, 3/4 in weed's process (TLS, auth, relay)
  PUT of 4 KiB        4400/s: the disk, two fsyncs each (the file, its directory)
  new connections     4400/s, stress taking half the CPUs: ~2 ms of weed's CPU each
                      with an RSA 2048 host key, half of it the signature (RSA 4096
                      signs in 4.5 ms, ECDSA P-256 in 0.02 ms)
  Basic, password     a bcrypt check per request, 40 ms or more: <= 25/s per core;
                      app tokens are looked up, bearer tokens checked in ~30 µs
  GET of 1 GiB        2500 MB/s for one client, 5400 MB/s in all: the CPUs (TLS)
  PUT of 64 MiB       900 MB/s for one client, 1300-1700 MB/s in all: the disk
  8192 clients        21400 PROPFIND/s, p99 1.25 s (unix_users.max_requests 20000)

Tuning, which the guide's Performance page explains. weed limits (as root) measures
weed on its machine, with a weed of its own on 127.0.0.1 and a load that grows until
weed or the machine gives, and suggests which of these to change: a weed.toml, a file
of /etc/sysctl.d and a drop-in of weed's unit, to review and install. It changes
nothing.
- unix_users.max_requests (4000 a worker), max_workers (256) and tpc.max_transfers
  (32) answer 503 beyond; max_storage_calls (256) bounds a worker's threads, and is
  for storage that serves many calls at once (NFS) to raise.
- systemd's TasksMax= defaults to 15% of kernel.threads-max (71736 on the laptop),
  and 256 workers of 285 threads, as they are when the storage hangs, are 73000: a
  process that cannot make a thread dies, weed's own too. The unit sets
  TasksMax=infinity, and cgroup_limits' pids.max bounds each account.
- Across long distances, a TCP connection carries at most one buffer each round
  trip: 4 MiB by default when sending, 42 MB/s at 100 ms. Raise the maximum of
  net.ipv4.tcp_wmem and tcp_rmem to twice bandwidth × RTT (256 MiB for 10 Gb/s at
  100 ms); net.core.wmem_max and rmem_max bound only what programs set themselves.
- With conntrack (firewalld), nf_conntrack_max bounds the connections, each kept 120 s
  after it closes: 262144 entries hold ~2000 new connections a second.
- The listen queue is net.core.somaxconn (4096); raise it only if nstat's
  TcpExtListenOverflows grows (it stayed 0 with 8192 clients).


Testing

    make test          unit and end-to-end tests (go test -race ./...); the tests of
                       request handling serve files in the test process, as its user
    make test-root     the same as root, adding the tests of worker processes, Unix
                       accounts and mounts (uses sudo)
    make test-cgroups  the cgroups of worker processes, as root in a cgroup of their
                       own (sudo, systemd-run)
    make test-systemd  weed's RPM, built and installed as the guide says
                       (Installation): its unit, as the account weed, with the
                       sandboxing above, then as root, and storage unmounted from
                       and mounted over the exported directory, in a privileged
                       AlmaLinux 10 container that boots systemd
                       (test/systemd/systemd.sh, Podman); WEED= or RPM= tests those
    make test-vm       the same tests on an AlmaLinux 10 virtual machine, SELinux
                       enforcing, and that SELinux denied weed nothing (test/vm/vm.sh,
                       qemu with KVM); RPM= tests that RPM
    make interop       interoperability tests (test/interop/interop.sh, Podman)
    make interop-storage STORAGE=xrootd-cluster
                       copies between weed and another storage system, one of
                       test/interop/storage/ (test/interop/storage.sh, Podman)
    make find-limits   weed limits on this machine (sudo): CONFIG=, DATA= the storage
                       (/var/tmp), ACCOUNT= (yours); the results are in
                       test/limits/out; ARGS="..." go to weed limits
    make find-limits-users
                       the same with USERS accounts (100), and crowds of thousands of
                       clients spread over them (test/limits/users.sh, Podman)
    make check         gofmt and go vet; make fuzz, make cross, make vulncheck and
                       make bench run the rest; make help lists every target

Everything runs on the machine, which must be Linux, but make test-systemd, make
interop, make interop-storage and make find-limits-users: they install units,
accounts, packages and a CA, and so run in Podman containers (sudo podman; the
interoperability tests also run with your own, with ROOTLESS=1).
make test runs every test but those that need root, which make test-root runs with
sudo: of worker processes and Unix accounts, and TestLandlockRemount
(internal/worker) and TestConfinedMounts (internal/landlock), which mount an ext4
image (mkfs.ext4) and tmpfs in their temporary directories, beneath, over and away
from directories that Landlock rules name.

The interoperability tests run weed in an AlmaLinux 10 container against real WLCG
software, from EPEL: gfal2, davix and curl as clients; XRootD (with its macaroons,
SciTokens and HTTP-TPC plugins) as a second implementation; and a test token issuer.
They cover X.509 proxies, macaroons, tokens, revocation with SIGHUP, metrics, Unix
accounts, bans, and third-party copies in both directions between two weed servers
and between weed and XRootD. make interop-storage runs another storage system in its
own containers, from test/interop/storage/<name>/, next to weed, and has each of them
pull from and push to the other, as gfal2 asks with an X.509 proxy: xrootd-cluster is
an XRootD redirector and data server; dcache is dCache's own image, with PostgreSQL,
whose WebDAV door sends clients to its pool; storm is StoRM WebDAV's own image, which
gives macaroons only to VOMS proxies, so gfal2 has one there; eos is EOS 5 from its
EL9 RPMs, QuarkDB, an MGM and an FST in one container, whose MGM redirects an upload
to the FST without waiting for its body, as CERN's EOS instances do. Each parser also has a fuzz test (go test -fuzz). CI
(.github/workflows/ci.yml) runs on Linux: the tests with -race and as root, go vet,
gofmt, govulncheck, builds for amd64 and arm64, the fuzz tests, the interoperability
tests (those with other storage systems without holding up a release), make
test-systemd and make test-vm, which it runs again on a release's RPM. It also makes
the administration guide from docs/src,
fails if docs/html is not what make docs makes, and publishes it on GitHub Pages from
the main branch: the guide of the latest release, and main's under dev/. For a tag, it
makes the release (see Releases).

test/stress finds what a weed server sustains. For each scenario (small files read,
written and listed, new TLS connections, downloads and uploads of large files, each
authentication method, many accounts), it doubles the number of concurrent clients
until throughput stops growing, more than 1% of requests fail, or the p99 latency
passes 2 seconds, and reports each step: requests per second, MB/s, latency, errors,
and the CPU it used. On weed's machine, -cgroup adds the CPU and memory weed used, and
what seems to limit it: the CPUs, or something else (the disk, the network, waiting).
Two scenarios grow a crowd instead, of up to 8192 clients (-clients) that each hold
a connection and stay from one step to the next: clients make a small GET every
second, slow-download read the large file at 1 MiB/s each, as jobs across a WAN do.
They report what each client adds to weed's memory and to the machine's, and stop
when clients fall behind, or the machine has used 90% of its memory. It works in a
directory of its own below the URL it is given, and removes it.

weed limits runs it on weed's machine against a weed of its own, serving one account,
which authenticates with a certificate, a token and a password, in a systemd scope of
its own whose CPU and memory stress reports; make find-limits-users against weed
serving many accounts in a Podman container, with the crowds spread over them
(-crowd-accounts).
On weed's machine, the load shares the CPUs with weed. To measure the machine that
will serve, run weed there as it will serve, and stress from another machine:

    go build -o stress ./test/stress
    ./stress -url https://weed.example.org/webdav/home/alice \
        -cert usercert.pem -key userkey.pem -ca /etc/grid-security/certificates

stress -h lists the scenarios and options; -json writes the results as JSON.


Releases

CHANGELOG.md has the changes of each version, the newest first, and the guide has it
as a page. A change that users or administrators may notice adds a line to its first
section, Unreleased, which the first change after a release begins; one that is not
compatible goes under Incompatible changes, and makes the next release a new major
version, or until 1.0.0 a new minor one (the guide's Upgrading, Versions, says which
are).

A release is a tag vMAJOR.MINOR.PATCH on main. Its commit names the version and the
day as the first section of CHANGELOG.md, in place of Unreleased, and has the guide
that make docs then makes, whose header says the version. From v2 on, the path of the
module, in go.mod and the imports, ends in the major version (as
github.com/labkode/weed/v2), which Go needs to take the tag for weed's version:

    sed -i 's/^## Unreleased$/## v1.2.0 (2026-11-20)/' CHANGELOG.md
    make docs
    git commit -am "weed v1.2.0"
    git tag -a v1.2.0 -m "weed v1.2.0"
    git push origin main v1.2.0

CI then runs as for every commit and, once it passes, release/dist.sh builds weed for
linux/amd64 and linux/arm64 with cgo on AlmaLinux 10, each on a runner of its
architecture, release/rpm.sh makes its RPM (packaging/weed.spec, of that weed),
test/systemd/systemd.sh tests the RPM as the guide installs it, and the release on
GitHub gets the archives (weed, README.txt, CHANGELOG.md, LICENSE and the guide), the
RPMs, SHA256SUMS, and the version's section of the changelog as its notes. Pushing
main with the tag publishes the release's guide on GitHub Pages. make dist builds the
archive of a tagged commit on an EL10 machine, for its architecture, and
release/rpm.sh dist/weed-*.tar.gz its RPM (rpm-build and systemd-rpm-macros).


Not implemented

* X.509 credential delegation for TPC (Credential: gridsite): use tokens or
  macaroons in TransferHeaderAuthorization
* Authorization by token groups alone: a token needs storage scopes even when its
  groups choose its Unix account
* Systems other than Linux, on which weed does not build
* WebDAV locks across accounts: each worker keeps its own


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
