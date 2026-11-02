WEED: WEbdav Exporter Daemon

WEED exports a local directory over WebDAV (RFC 4918) under /webdav/, and implements
WLCG HTTP third-party copy (pull and push) with the data-integrity extension described
in https://github.com/labkode/wlcg-tpc. Clients authenticate with X.509 certificates
and proxies, WLCG/SciTokens bearer tokens (which browsers can get from an OIDC login
page), macaroons or passwords.

Every request accesses files as the Unix account that its credentials map to, from a
worker process running as that account (see Unix accounts), so weed serves on Linux,
and runs as root. It targets AlmaLinux 10 (EL10), which its tests run on. macOS is
only for developing weed, which serves there as the account that runs it (see
Development on macOS); other systems only get the helpers (weed utils, config,
check, version). weed does not need systemd: any supervisor runs it, SIGHUP reloads
it, SIGTERM stops it, and it exits with status 75 to be started again (see the
guide's Installation, Without systemd).

    go build && sudo ./weed

serves the current directory at http://127.0.0.1:9000/webdav/ to local clients,
without authentication, as the account nobody (so they can read and write what nobody
can), with its metrics, status and dashboard at http://127.0.0.1:9000/metrics,
/status and /dashboard/. Anything else is set in a configuration file:

    ./weed config >weed.toml     every option, its default and what it does
    ./weed check -config weed.toml   would weed start with it? (see What runs)
    ./weed -config weed.toml
    ./weed version

Helpers:

    ./weed utils password <user> <password>   add a bcrypt entry to .htpasswd
    ./weed utils token generate <user>        create an app token in .app-tokens

The administration guide, docs/html/index.html, explains how to install, set up and
run weed, with every option, metric and command. Its pages are written in Markdown in
docs/src, and made into docs/html by pandoc: "make docs" after changing them.


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
* PROPFIND with Depth: infinity (or no Depth) is refused (403).
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
requests get 503 (see "Storage that does not answer" below). Workers log through weed,
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

weed runs as root, which it needs to start workers as other accounts, and which the
systemd unit in What runs does. Otherwise, it needs the CAP_SETUID and CAP_SETGID
capabilities, or it does not start ("weed must run as root, ..."):

    User=weed
    AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE
    Delegate=yes           # for unix_users.cgroups
    RuntimeDirectory=weed  # for admin.socket (see Banning users)
    StateDirectory=weed    # for admin.bans

Downloads relayed from workers run at ~92% of the speed of serving files directly,
and uploads at the same speed (Linux, 1 GiB files over loopback without TLS:
~5200 against ~5600 MB/s; WEED_BENCH_MIB=1024 make bench-workers measures it). That
needs 1 MiB socket buffers, which root gets; as another user, also raise
net.core.wmem_max and net.core.rmem_max to 1048576, or downloads lose a third.
Larger buffers would gain a few percent of one stream, but a client that reads
slower than its worker keeps them full: 4 MiB took 7 MB of memory per slow client,
1 MiB takes 2.7 MB (make find-limits, slow-download).

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
* Symbolic links: workers open every name beneath the exported directory (Go's
  os.Root), and follow a link only when it is relative and stays inside. A link
  that leads outside, and every absolute link (even one to a file inside), gets 403,
  is left out of listings, and is logged ("refused a name that leads outside the
  exported directory"). Otherwise, a user who can make links there (over ssh, NFS)
  could have weed read whatever the account can, such as /etc.
* Landlock (Linux 5.19 or later, with landlock among the security modules, lsm=):
  weed confines itself and each worker as it starts it, and does not start without
  it. Whatever a bug in a worker tries, it may write beneath the exported directory
  alone, and read only beneath it and /etc, /usr, /lib, /proc and /sys/fs/cgroup (and
  tpc.ca_path, SSL_CERT_FILE and SSL_CERT_DIR), whatever the permissions: not /home,
  /tmp, nor files of other services. It may execute weed alone (and, for a build with
  cgo, its dynamic loader, which can run other programs, confined the same); it cannot
  make symbolic links, devices, sockets or FIFOs; from Linux 6.7, it binds no TCP port,
  and connects to none unless tpc.enabled, for third-party copies (Landlock does not
  confine UDP); from Linux 6.12, it signals no process (but on RHEL 9's kernels, which
  lack that) and connects to no abstract Unix socket outside its confinement. weed
  logs the rules as it starts ("workers are confined with Landlock"). Each worker
  checks that it is confined, and refuses to serve otherwise. On some file systems,
  such as Docker Desktop's mounts of the host, Landlock refuses every access whatever
  its rules: weed then does not start, and says so, if the exported directory or
  weed's binary is on one. Landlock does not cover stat, chmod, chown, utime and
  extended attributes: on files outside the exported directory, permissions alone
  keep those.
And weed's own process, which terminates TLS and authenticates requests, as root: it
may write the exported directory, the directories of server.log_file, admin.socket
and admin.bans, and its cgroup, and read only those, the system's files (as workers)
and the files that its configuration names; from Linux 6.7, it binds only its ports,
and connects only to token issuers and for third-party copies. Landlock confines a
thread and what it executes, so weed executes itself again, from a thread that it
confines; it logs the rules as it does ("weed confines itself with Landlock"), and
refuses to start if it then is not confined. Confined to /, weed would reach
everything: it does not export /. Landlock confines to plain directories and to mount
points alike: a rule names the directory that its path leads to as weed starts (the
root of the storage mounted at /data, or the plain directory /data), and covers what
is beneath, storage mounted below it later included; not a storage mounted over it or
above it later (a remount), nor the directory beneath a storage that is unmounted.
weed looks at the directory every 5 seconds. When a storage is there in its place,
weed lets the requests in progress finish and exits with status 75, for its
supervisor to start it again, confined to it (systemd: Restart=on-failure);
meanwhile, requests get 503. When the storage that weed started on is no longer
mounted, weed does not exit: it refuses requests (503, /healthz too, the metric
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
  RuntimeDirectory=weed and StateDirectory=weed, which admin.socket and admin.bans
  need), ReadWritePaths=/data (the exported directory; and that of server.log_file),
  ProtectHome=yes (unless the exported directory is below /home), PrivateTmp=yes.
  ReadWritePaths= makes writable what /data is as weed starts, as Landlock does; weed
  starts again when that changes (above). It does not separate the accounts from each
  other. make test-systemd runs weed with these directives (see Testing); try others
  with weed check and a few requests of each kind.

cgroups. With unix_users.cgroups, the workers of each account run in a cgroup of
their own below weed's, which must be delegated to weed (systemd's Delegate=yes;
cgroup v2): weed moves into <its cgroup>/main and starts the workers of alice in <its
cgroup>/worker-alice, with the cpu, io, memory and pids controllers when they are
available. systemd-cgtop and systemd-cgls then show what each account uses, and
unix_users.cgroup_limits writes limits into the cgroup of every account:

    [unix_users]
    cgroup_limits = ["memory.max=8G", "pids.max=5000", "cpu.weight=100"]

pids.max counts threads, and a worker that cannot make one dies: keep it above
unix_users.max_requests. The Go runtime of a worker keeps below 90% of the lower of
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
has gone. The worker's other requests go on, and so do other accounts' workers; weed
itself never touches the files, but /healthz, which makes one stat of the exported
directory at a time, and the look of Landlock at it every 5 seconds (from one
goroutine, with what the kernel has cached): until it has first answered, requests
that would start a worker get 503. So that stuck threads cannot pile up until the
Go runtime stops the worker (at 10000), a worker counts its requests until it has
finished them, and refuses those beyond unix_users.max_requests with 503; an idle
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
server.log_file, so that logrotate can move it (postrotate: systemctl kill -s HUP
weed); under systemd, standard error goes to the journal.


Monitoring

/healthz, on the main port without authentication, answers 200 "ok", or 503 when
the exported directory cannot be stat'ed within 5 seconds (e.g. a hung network
filesystem). It makes one stat at a time: while one hangs, calls wait for it.

server.metrics_address = "localhost:9100" serves, without authentication, /healthz,
/status (see What runs), Prometheus metrics on /metrics, and a dashboard of both at
http://localhost:9100/: the browser reads them every 2 seconds and shows throughput,
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
weed, or let systemd do so.

systemd. weed is a Type=notify service: it tells systemd that it is ready once it
listens (so systemctl start fails when weed cannot start, and units ordered after
weed start once it serves), when it reloads, and when it stops, and keeps a status
line up to date:

    [Unit]
    After=network-online.target remote-fs.target
    StartLimitIntervalSec=0          # restart for ever

    [Service]
    # systemd >= 253; before, Type=notify and ExecReload=kill -HUP $MAINPID
    Type=notify-reload
    ExecStartPre=/usr/local/bin/weed check -config /etc/weed/weed.toml
    ExecStart=/usr/local/bin/weed -config /etc/weed/weed.toml
    Restart=on-failure               # also on status 75 (the exported directory moved)
    RestartSec=2s                    # then up to a minute apart (systemd >= 254)
    RestartSteps=5
    RestartMaxDelaySec=1min
    OOMPolicy=continue               # a worker killed for memory does not stop weed

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


Testing

    make test          unit and end-to-end tests (go test -race ./...); the tests of
                       request handling serve files in the test process, as its user
    make test-root     the same as root, adding the tests of worker processes and
                       Unix accounts (Linux, uses sudo)
    make test-linux    the same as root in a Linux container, e.g. from macOS (Docker)
    make test-cgroups  the cgroups of worker processes, in a privileged container
    make test-systemd  weed as the service of the guide (Installation): its unit,
                       with Delegate=yes and the sandboxing above, as root and as an
                       account of its own, and storage unmounted from and mounted
                       over the exported directory, in a privileged AlmaLinux 10
                       container that boots systemd (test/systemd/systemd.sh, Docker)
    make interop       interoperability tests (test/interop/interop.sh, Docker)
    make lab           weed with 22 Unix accounts under a load that does not stop, in
                       a container, to watch its dashboard, /status, /metrics and the
                       logs, with Prometheus and Grafana (test/lab/lab.sh, Docker);
                       make lab-ssh opens a shell in it, make lab-stop stops it
    make find-limits   the limits of weed on this machine: the lab without its load,
                       or limits, under a load that grows until weed or the
                       machine gives (test/stress, Docker); ARGS="..." go to stress
    make check         gofmt and go vet; make fuzz, make cross, make vulncheck and
                       make bench run the rest; make help lists every target

TestLandlockRemount (internal/worker) mounts an ext4 image again over the exported
directory, as a storage mounted again, and TestConfinedMounts (internal/landlock)
mounts storage beneath, over and away from directories that rules name: they need
root in a privileged container (and mkfs.ext4), and skip otherwise, as in make
test-linux.

Development on macOS. macOS is only for developing weed, not for serving: there,
./weed accesses files in its own process, as the account that runs it, whatever
identity a request has, and does not run as root. Authentication, checksums, locks,
third-party copies, bans, metrics, /status and the dashboard work as on Linux; worker
processes, Unix accounts, Landlock, cgroups and unix_users.limits do not. weed says
so as it starts, and /status shows "development" with the account. The control
plane's socket and the bans file, by default in /run/weed and /var/lib/weed, are in
the user's cache directory (~/Library/Caches/weed), also when a configuration sets
them to those defaults, as weed config prints them. make test runs every test but
those of worker processes and Unix accounts, which make test-linux runs in a
container; make lab runs weed as on a server.

The interoperability tests run weed in an AlmaLinux 10 container against real WLCG
software, from EPEL: gfal2, davix and curl as clients; XRootD (with its macaroons,
SciTokens and HTTP-TPC plugins) as a second implementation; and a test token issuer.
They cover X.509 proxies, macaroons, tokens, revocation with SIGHUP, metrics, Unix
accounts, bans, and third-party copies in both directions between two weed servers
and between weed and XRootD. Each parser also has a fuzz test (go test -fuzz). CI
(.github/workflows/ci.yml) runs the tests with -race on Linux and macOS and as root
on Linux, go vet, gofmt, govulncheck, cross-builds, the fuzz tests and the
interoperability tests.

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

make find-limits runs it in the lab's container, with weed's files on a Docker volume:
the load shares the CPUs with weed, and downloads read one file, from memory. To
measure the machine that will serve, run weed there as it will serve, and stress from
another machine:

    go build -o stress ./test/stress
    ./stress -url https://weed.example.org/webdav/home/alice \
        -cert usercert.pem -key userkey.pem -ca /etc/grid-security/certificates

stress -h lists the scenarios and options; -json writes the results as JSON.


Not implemented

* X.509 credential delegation for TPC (Credential: gridsite): use tokens or
  macaroons in TransferHeaderAuthorization
* Authorization by token groups alone: a token needs storage scopes even when its
  groups choose its Unix account
* Serving on systems other than Linux
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
