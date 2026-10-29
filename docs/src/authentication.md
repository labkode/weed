---
title: 'Authentication'
---

weed accepts X.509 certificates and proxies, WLCG and SciTokens bearer tokens, macaroons and passwords. Each method maps a client to a username, which must be a local account: the request then accesses files as that account (see [Unix accounts](unix-accounts.html)).

## How a request is authenticated {#order}

weed tries the enabled methods in this order: X.509, tokens, macaroons, passwords. The first one that accepts the request's credentials decides. Then:

- Credentials that are wrong, expired or of an unknown issuer get **401**.
- Valid credentials that do not allow the request get **403**: a DN that the grid-mapfile does not list, a token whose scopes do not cover the path, a user without a usable account, a [banned](banning.html) user.
- A request without credentials gets 401, unless anonymous requests are allowed.

Every failure is logged at INFO, as "authentication failed", with the method and the reason (see [Troubleshooting](troubleshooting.html#refused)). The request's record names the user that the credentials map to, also when they are refused with 403.

/proc/whoami shows how weed sees a client, and the account it would be served as:

    $ curl -H "Authorization: Bearer $TOKEN" https://weed.example.org/proc/whoami
    === WebDAV Server - Who Am I ===

    Status: Authenticated
    Username: cms001
    Authentication Method: token
    Unix Account: cms001 (uid 2001, gid 2001, groups [2001])

    Authentication Details:
      scopes: storage.read:/ storage.create:/cms
      expires: 2026-10-29 10:06:57 +0000 UTC
      groups: /cms/production
      issuer: https://iam.example.org/
      subject: 5f2c1d
    ...

## X.509 certificates and proxies {#x509}

    [tls]
    enabled = true
    cert = "/etc/grid-security/hostcert.pem"
    key = "/etc/grid-security/hostkey.pem"

    [x509]
    enabled = true
    ca = "/etc/grid-security/certificates"
    crl_path = "/etc/grid-security/certificates"
    gridmap = "/etc/grid-security/grid-mapfile"

`x509.ca` is a PEM file or a directory of CA certificates, such as /etc/grid-security/certificates. weed accepts end-entity certificates, and RFC 3820 and legacy Globus proxies.

### The grid-mapfile

Only the certificates whose DN the grid-mapfile lists are accepted, as the account it names. A certificate of a trusted CA whose DN is not listed gets 403, so trusting every IGTF CA does not let in every grid user. weed does not start without a readable grid-mapfile when X.509 is enabled.

    "/DC=org/DC=example/OU=Users/CN=Alice Smith" alice
    "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=jdoe/CN=123456/CN=John Doe" jdoe
    "/DC=ch/DC=cern/OU=computers/CN=cmsprod.cern.ch" cms001,cmsprod

DNs are in the OpenSSL format, in certificate order. A proxy is mapped by the DN of the certificate it was made from. When a line names several accounts, the first is used. Lines starting with \# are comments. To revoke a user's access, remove the line and reload (see [Reloading](reloading.html)).

### Proxies

weed refuses a proxy chain when a proxy:

- has a policy other than inherit-all or limited (e.g. independent);
- is followed by more proxies than its path length allows;
- is unrestricted but issued by a limited proxy;
- is legacy and RFC 3820 in the same chain;
- is expired or not yet valid, or its issuer lacks the digitalSignature key usage.

Limited proxies are accepted: they are meant for data access. /proc/x509 shows how weed sees the certificate that a client presents.

### Revocation {#crls}

With `x509.crl_path`, weed checks certificates against CRLs, PEM or DER, read from a file or a directory such as /etc/grid-security/certificates, where fetch-crl keeps them as \<hash\>.r0. A certificate is checked against the newest current CRL that its issuer signed.

`x509.crl_mode` says what happens when the issuer has no current CRL:

require (the default)
:   the certificate is refused (401). An expired CRL fails closed: if fetch-crl stops working, the users of that CA are refused once their CA's CRL expires.

if-valid
:   certificates are checked against the CRLs that are present and current, and accepted otherwise.

The metric `weed_crl_expiry_timestamp_seconds` says when the first CA runs out of current CRLs: alert well before. Without `x509.crl_path`, revoked certificates are accepted.

## WLCG and SciTokens bearer tokens {#tokens}

    [tokens]
    issuers = "/etc/weed/issuers.json"

weed accepts the JWTs of the issuers that the file lists, as the WLCG Common JWT Profiles and SciTokens define them. The file is a JSON list:

    [{"issuer": "https://iam.example.org/",
      "audiences": ["https://weed.example.org"],
      "base_path": "/",
      "users": [{"group": "/cms/production", "user": "cms001"},
                {"sub": "3f2a...", "user": "jdoe"}]}]

issuer
:   the issuer's URL, exactly as in its tokens' iss claim.

audiences
:   the audiences weed accepts: a token's aud must include one of them, or https://wlcg.cern.ch/jwt/v1/any.

base_path
:   the path, below the exported directory, that the paths of the issuer's scopes are relative to (default "/").

users
:   rules that map tokens to accounts (see below). Without them, a token's account is its sub claim.

weed checks a token's signature with the keys that its issuer publishes, found through /.well-known/openid-configuration (or oauth-authorization-server). Keys are cached and refetched every hour, and fetched at most once a minute per issuer, so that forged tokens cannot make weed flood an issuer. If an issuer is down, its known keys keep working for 2 days after they were last fetched; after that, its tokens get 401 until it is back. Use `tokens.ca_path` to trust CAs other than the system's for the issuers.

A token is refused with 401 if it is expired (1 minute of clock skew is allowed), if its aud is not accepted, or if its wlcg.ver is not 1.x (SciTokens have none).

### Scopes

Scopes grant access to a path and everything below it. Paths are relative to the issuer's base_path.

| Scope | Allows |
|----|----|
| storage.read:\<path\> | read, list and stat (and the SciTokens read) |
| storage.create:\<path\> | create files and directories, rename, stat; never replace or delete data: PUT, COPY, MOVE and TPC pull onto an existing file get 403, before any data is sent |
| storage.modify:\<path\> | also overwrite and delete (and the SciTokens write) |
| storage.stage, storage.poll | nothing: they are for tape |

A path that ends in / is a directory: storage.create:/a/b/ allows creating the directory /a/b and anything in it, but not a file named /a/b. A storage scope without a path makes the token invalid (401). A token without storage scopes gets 403: groups choose an account, but grant nothing by themselves.

What each request needs:

| Request | Scope |
|----|----|
| GET | read |
| HEAD, PROPFIND Depth: 0 | read, create or modify |
| PROPFIND Depth: 1 | read |
| PUT | create (new files only) or modify |
| MKCOL, LOCK, UNLOCK | create or modify |
| DELETE, PROPPATCH | modify |
| COPY (local) | read on the source; create or modify on the destination |
| MOVE | create or modify on the source and the destination |
| COPY (TPC pull) | create or modify |
| COPY (TPC push) | read |

### Which account a token is served as

The users rules of an issuer map its tokens to accounts. The first rule that matches decides; a token that no rule matches gets 403.

    "users": [{"sub": "3f2a...", "user": "jdoe"},
              {"group": "/cms/production", "user": "cmsprod"},
              {"sub": "9c1e...", "group": "/cms", "user": "cmsuser"},
              {"user": "cmsguest"}]

A rule matches the tokens whose sub equals its "sub", and whose wlcg.groups contains its "group", exactly: /cms does not match /cms/production. A field that a rule leaves out matches any token, so a rule with only "user" is a default.

## The OIDC login page {#oidc}

For users with a browser, weed can serve a login page, at /auth/oidc, that gives out a token of one of the token issuers. Users log in at the issuer, and get a page with the access token, the account weed serves it as, its scopes and expiry, and how to use it with curl and gfal2.

    [oidc]
    enabled = true
    issuer = "https://iam.example.org/"
    client_id = "..."
    client_secret = "..."
    redirect_url = "https://weed.example.org/oidc_redirect"
    scopes = ["openid", "storage.read:/", "storage.modify:/"]

Register weed as a client at the issuer, with that redirect URL. The issuer must be listed in `tokens.issuers`: weed does not start otherwise. Logins ask for `oidc.scopes`, of which the issuer grants those its policies allow, and for `oidc.audience` if it is set (the audience parameter of INDIGO IAM). weed checks the token as for any request before showing it: a token that weed would refuse is not given out, and the page says why. For tokens that renew themselves, users should use oidc-agent instead.

weed keeps no sessions: a login in progress is in a cookie of the browser, used once. Any weed with the same configuration completes a login that another started, so a login works behind a load balancer.

## Macaroons

    [macaroons]
    enabled = true
    secret_key = "...at least 32 characters, e.g. openssl rand -hex 32..."

Any authenticated user can ask weed for a macaroon for a path, by POSTing to it. gfal2 and FTS do this for third-party copies:

    $ curl --cert alice.pem --key alice.key -X POST https://weed.example.org/webdav/alice/ \
        -H 'Content-Type: application/macaroon-request' \
        -d '{"caveats": ["activity:DOWNLOAD,LIST"], "validity": "PT1H"}'
    {"expires_in":3599,"macaroon":"AgELd2VlZC13ZWJkYXYCIDRhOGNi..."}

The macaroon is then a bearer token (Authorization: Bearer), valid for that path and below only, and as the user who asked for it. It always expires: the validity defaults to and is capped at `macaroons.max_validity` (24h). A macaroon asked for with a macaroon keeps every restriction of the first. A token cannot be used to ask for a macaroon, which would not be bound by the token's scopes.

Caveats a client may ask for: `activity:` (DOWNLOAD, UPLOAD, LIST, MANAGE, DELETE, READ_METADATA, UPDATE_METADATA), `path:`, `before:` (an RFC 3339 time) and `ip:` (addresses or CIDRs). Unknown caveats are refused.

Every weed that shares the secret key accepts the macaroons of the others. Changing the key invalidates every macaroon given out; it takes a restart.

## Passwords and app tokens {#basic}

    [basic]
    enabled = true
    htpasswd = "/etc/weed/htpasswd"
    app_tokens = "/etc/weed/app-tokens"

HTTP Basic authentication checks passwords against the bcrypt entries of an htpasswd file, or against app tokens: random tokens, one per line as token:username, that a user gives as their password. Basic credentials are clear text without TLS: enable \[tls\] with \[basic\].

*weed utils password* and *weed utils token generate* add entries to .htpasswd and .app-tokens in the current directory:

    # cd /etc/weed
    # weed utils password bob 's3cret'
    Added user 'bob' to .htpasswd
    # weed utils token generate bob
    Generated token for user 'bob': 23bb59e76eeeb0228d5a1d1b53f6bda289ce9e43fae29b85d64215d5422a5127
    Token saved to .app-tokens

Point `basic.htpasswd` and `basic.app_tokens` at those files, or use htpasswd -B. weed re-reads both on reload, so new users need no restart.

## Anonymous requests {#anonymous}

With `server.anonymous`, requests without credentials are served as the account nobody. weed allows it only when `server.address` is a loopback address, so that only local clients reach it (but every local user does). It is the default without a configuration file. Credentials that an enabled method refuses still get 401.
