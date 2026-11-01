---
title: 'Getting started'
---

This page first tries weed without any configuration, then sets up a grid storage node step by step: X.509 certificates with a grid-mapfile, WLCG tokens, and third-party copy.

## Trying weed {#trying}

Without a configuration file, weed serves the current directory at http://127.0.0.1:9000/webdav/ to local clients only, without authentication, as the account nobody. Nobody must be able to write the directory for uploads to work:

    $ mkdir /tmp/demo && chmod 1777 /tmp/demo && cd /tmp/demo
    $ sudo weed

In another terminal:

    $ curl -T /etc/hosts http://127.0.0.1:9000/webdav/hosts
    $ curl http://127.0.0.1:9000/webdav/hosts
    127.0.0.1   localhost
    ...
    $ ls -l /tmp/demo
    -rw-r--r-- 1 nobody nobody 199 Oct 29 09:06 hosts

The file belongs to nobody, the account of anonymous requests. Without a configuration file, the same port also serves /metrics and /status (see [Monitoring](monitoring.html)). Stop weed with Ctrl-C.

### On macOS, for development {#macos}

macOS is only for developing weed, not for serving: there, weed accesses files in its own process, as the account that runs it, whatever identity a request has. It does not run as root, which would give every identity every file:

    $ mkdir /tmp/demo && cd /tmp/demo
    $ weed
    level=WARN msg="development mode, as on macOS: weed serves files in its own process, as the account that runs it, for every identity; ..." account=alice

Authentication, checksums, locks, third-party copies, bans, metrics, /status and the dashboard work as on Linux. Worker processes, Unix accounts, Landlock, cgroups, network rates and `unix_users.limits` do not, and /status shows `"development": "alice"`. The control plane's socket and the bans file, by default in /run/weed and /var/lib/weed, are in the user's cache directory (~/Library/Caches/weed on macOS), also when a configuration file sets them to those defaults. To try weed as on a server from a Mac, use the lab (`make lab`, Docker), and `make test-linux` for the tests of worker processes.

## A grid storage node {#storage-node}

The rest of this page sets up weed.example.org, which exports /data on port 443. Alice authenticates with her certificate, as the account alice; the CMS production jobs with WLCG tokens from https://iam.example.org/, as the account cms001.

### 1. Accounts and directories

Every identity maps to a local account, which accesses the files. Create the accounts (or have them in LDAP), and give each a directory:

    # useradd -M -u 1001 alice
    # useradd -M -u 2001 cms001
    # mkdir -p /data/alice /data/cms
    # chown alice: /data/alice && chown cms001: /data/cms
    # chmod 755 /data

The accounts need search permission on /data and its parents. weed refuses root as an account.

### 2. Host certificate, CAs and CRLs

weed serves HTTPS with the host certificate, and checks client certificates against the CAs, as other grid services do:

    /etc/grid-security/hostcert.pem
    /etc/grid-security/hostkey.pem              (mode 0400)
    /etc/grid-security/certificates/            the IGTF CAs (e.g. the ca-policy-egi-core
                                                package), and their CRLs, kept current
                                                by fetch-crl

By default weed refuses certificates whose CA has no current CRL, so run fetch-crl regularly (its packages do) and see [Reloading](reloading.html#crls).

### 3. The grid-mapfile

Only the certificates whose DN the grid-mapfile lists are accepted, as the account it names. Trusting every IGTF CA does not let in every grid user. /etc/grid-security/grid-mapfile:

    "/DC=org/DC=example/OU=Users/CN=Alice Smith" alice

### 4. The token issuer

/etc/weed/issuers.json lists the issuers whose tokens weed accepts, the audience they must be for, and which account a token is served as. Here, tokens of the group /cms/production are cms001's:

    [{"issuer": "https://iam.example.org/",
      "audiences": ["https://weed.example.org"],
      "users": [{"group": "/cms/production", "user": "cms001"}]}]

### 5. The configuration file

/etc/weed/weed.toml:

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

    [macaroons]
    enabled = true
    secret_key = "...the output of: openssl rand -hex 32..."

The file holds a secret, so make it readable by root only: weed refuses a file with secrets that every user can read.

    # chmod 600 /etc/weed/weed.toml

The grid-mapfile is at its default path, /etc/grid-security/grid-mapfile. `tpc.ca_path` lets weed verify the other storage endpoints with the IGTF CAs, and macaroons let gfal2 and FTS hand out credentials for third-party copies. *weed config* prints every option, with its default and what it does; [Configuration options](options.html) lists them.

### 6. Checking and starting

    # weed check -config /etc/weed/weed.toml
    /etc/weed/weed.toml: weed would start with it (sha256 6794c30b95c0972e5a032630bb90ccdf474c3df01a9dd983f88c9fdc5baf417e)
    # systemctl enable --now weed

*weed check* reads every file the configuration names, as weed does at startup, and says what would stop it otherwise:

    # weed check -config /etc/weed/weed.toml
    weed would not start with /etc/weed/weed.toml: failed to load the grid-mapfile: open /etc/grid-security/grid-mapfile: no such file or directory

At startup weed logs what it loaded, which build runs, every option (secrets redacted), what each authentication method accepts, and where it listens:

    level=INFO msg="loaded grid-mapfile" file=/etc/grid-security/grid-mapfile entries=1
    level=INFO msg="loaded CA certificates" path=/etc/grid-security/certificates certificates=1
    level=INFO msg="loaded CRLs" path=/etc/grid-security/certificates crls=1 mode=require
    level=INFO msg="loaded token issuers" file=/etc/weed/issuers.json issuers=1
    level=INFO msg="started a worker" worker.user=nobody worker.pid=108 account.name=nobody account.uid=65534 account.gid=65534 account.groups=[65534]
    level=INFO msg="worker stopped" worker.user=nobody worker.pid=108
    level=INFO msg="files are accessed by a worker process per Unix account" idle_timeout=10m0s max_workers=256 max_requests=4000 cgroups=false
    level=INFO msg="starting weed" version=v1.2.0 commit=46a37813bc81d7a1b9a8b1e2a9e1f3c3e6c2a0d4 ... pid=95 executable=/usr/local/bin/weed dir=/data tls=true authentication=x509,tokens,macaroons tpc=true reload_interval=1h0m0s
    level=INFO msg=configuration file=/etc/weed/weed.toml sha256=6794c30b95c0972e5a032630bb90ccdf474c3df01a9dd983f88c9fdc5baf417e config.server.address="" config.server.port=443 config.server.dir=/data ...
    level=INFO msg="X.509 authentication" ca=/etc/grid-security/certificates gridmap=/etc/grid-security/grid-mapfile crl_path=/etc/grid-security/certificates crl_mode=require
    level=INFO msg="token issuer" issuer=https://iam.example.org/ base_path=/ audiences="[https://weed.example.org https://wlcg.cern.ch/jwt/v1/any]"
    level=INFO msg=macaroons location=weed-webdav max_validity=24h0m0s
    level=INFO msg="third-party copy" max_transfers=32 allow_http=false allow_local=false allow_private=false
    level=INFO msg=listening address=[::]:443 scheme=https
    level=INFO msg="serving the control plane" socket=/run/weed/admin.sock
    level=INFO msg="serving metrics" address=127.0.0.1:9100

(The time of each record is left out here.) The worker that starts and stops as nobody is weed checking, before it serves, that it can start workers.

### 7. Trying it

/proc/whoami tells how weed sees a client: who it is, and the account it is served as.

    $ curl --cert alice.pem --key alice.key https://weed.example.org/proc/whoami
    === WebDAV Server - Who Am I ===

    Status: Authenticated
    Username: alice
    Authentication Method: X.509 Certificate
    Unix Account: alice (uid 1001, gid 1001, groups [1001])

    Authentication Details:
      distinguished_name: /DC=org/DC=example/OU=Users/CN=Alice Smith
    ...
    $ curl --cert alice.pem --key alice.key -T /etc/hosts https://weed.example.org/webdav/alice/hosts
    $ gfal-ls -l davs://weed.example.org/webdav/alice/
    -rwxrwxrwx   0 0     0           199 Oct 29 09:06 hosts
    $ gfal-copy file:///etc/services davs://weed.example.org/webdav/alice/services
    Copying 692252 bytes file:///etc/services => davs://weed.example.org/webdav/alice/services
    $ gfal-sum davs://weed.example.org/webdav/alice/services ADLER32
    davs://weed.example.org/webdav/alice/services 3c5e9d34

gfal2 uses the proxy in X509_USER_PROXY. With a token of the group /cms/production:

    $ curl -H "Authorization: Bearer $TOKEN" -T /etc/services https://weed.example.org/webdav/cms/services
    $ ls -l /data/alice /data/cms
    /data/alice:
    -rw-r--r-- 1 alice alice    199 Oct 29 09:06 hosts
    -rw-r--r-- 1 alice alice 692252 Oct 29 09:06 services

    /data/cms:
    -rw-r--r-- 1 cms001 cms001 692252 Oct 29 09:06 services

Each file belongs to the account that wrote it, and *ps* shows a worker for each:

    $ ps -o user,pid,ppid,args -C weed
    USER         PID    PPID COMMAND
    root          95       1 weed -config /etc/weed/weed.toml
    alice        127      95 weed worker alice
    cms001       166      95 weed worker cms001

A certificate that the grid-mapfile does not list gets 403, and the log says why:

    level=INFO msg="authentication failed" method=x509 error="forbidden: /DC=org/DC=example/OU=Users/CN=Somebody Else is not in the grid-mapfile" request_id=2daaa43c
    level=INFO msg=request method=GET path=/webdav/alice/ proto=HTTP/1.1 status=403 bytes=10 duration=288.167µs user=nobody remote=192.0.2.7:52430 user_agent=curl/7.76.1 request_id=2daaa43c

Next: [Authentication](authentication.html) explains each method in full, [Monitoring](monitoring.html) what to watch, and [Troubleshooting](troubleshooting.html) what the usual errors mean.
