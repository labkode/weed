---
title: 'Configuration'
---

weed reads one configuration file, in TOML, named with `-config`. Every option is optional. [Configuration options](options.html) lists them all.

## The file {#file}

*weed config* prints a file that sets every option to its default, and says what each one does. It is a good start:

    # weed config >/etc/weed/weed.toml
    # head -20 /etc/weed/weed.toml
    # weed configuration: weed -config weed.toml
    #
    # Every option is optional: this file sets each one to its default. Without a
    # configuration file, weed serves the current directory to local clients without
    # authentication (address = "127.0.0.1" and anonymous = true in [server]).
    # Durations are strings such as "90s", "10m" or "24h". weed refuses to read a file
    # that holds secrets (macaroons.secret_key, oidc.client_secret) if every user can.

    # Server
    [server]
    # address to listen on ("" for all interfaces)
    address = ""
    # TCP port
    port = 9000
    # directory exported under /webdav/
    dir = "."
    ...

The sections are:

| Section | What it sets |
|----|----|
| [\[server\]](options.html#server) | the port, the exported directory, logging, metrics, reloading |
| [\[tls\]](options.html#tls) | HTTPS and the host certificate |
| [\[x509\]](options.html#x509) | client certificates and proxies: CAs, CRLs, grid-mapfile |
| [\[basic\]](options.html#basic) | passwords and app tokens |
| [\[oidc\]](options.html#oidc) | the login page that gives out tokens to browsers |
| [\[macaroons\]](options.html#macaroons) | macaroons, which weed mints |
| [\[tokens\]](options.html#tokens) | WLCG and SciTokens bearer tokens: the issuers |
| [\[tpc\]](options.html#tpc) | third-party copy |
| [\[unix_users\]](options.html#unix_users) | worker processes: idle time, how many, cgroups, the limits of some users and groups |
| [\[admin\]](options.html#admin) | the control plane's socket, and the banned users' file |

## Rules

- Unknown sections and options are errors, so a misspelt option stops weed instead of being ignored:

      # weed check -config /etc/weed/weed.toml
      weed would not start with /etc/weed/weed.toml: unknown option server.prot

- Durations are strings such as `"90s"`, `"10m"` or `"24h"`.

- weed refuses to read a file that holds secrets (`macaroons.secret_key`, `oidc.client_secret`) if every user can read it:

      weed would not start with /etc/weed/weed.toml: /etc/weed/weed.toml holds secrets but every user can read it (chmod o-r /etc/weed/weed.toml)

- Paths are used as they are written. A relative path is relative to the directory weed starts in, which is / under systemd. Write absolute paths: the defaults of `basic.htpasswd` (.htpasswd) and `tls.cert` (server.crt), for example, are relative.

- Some options need others: `x509.enabled` needs `tls.enabled` and `x509.ca`; `server.anonymous` needs a loopback `server.address`. weed says which.

## Changing the configuration {#changes}

weed reads the file only at startup: changes take effect when weed restarts. The credential files that it names (grid-mapfile, CAs, CRLs, token issuers, passwords, the host certificate) are different: weed re-reads them while it runs (see [Reloading](reloading.html)).

So that you know when the file and the running weed differ, weed looks at the file every minute, and says when a restart would change something. It logs a warning naming the options that changed, and an error if weed would not start with the file:

    level=WARN msg="restart pending: the configuration file has changed: server.port" reason=config

/status and the metric `weed_restart_pending` say it too, and so does *systemctl status*. Changes to comments or layout are not reported. See [What runs](what-runs.html).

Before restarting, check the file:

    # weed check -config /etc/weed/weed.toml
    /etc/weed/weed.toml: weed would start with it (sha256 43a0e6eeb1b2d1727339feb3ac4bd77171b428ad25a44e22822813d054959667)
    # systemctl restart weed

## Without a file {#quickstart}

Without `-config`, weed runs with the defaults, except that it listens on 127.0.0.1 only and serves requests without credentials as the account nobody (`server.address = "127.0.0.1"`, `server.anonymous = true`). Its port also serves /metrics and /status, since its clients are local. This is for trying weed (see [Getting started](getting-started.html#trying)).

## Examples

### A grid storage node

X.509 with a grid-mapfile, WLCG tokens, macaroons and third-party copy: see [Getting started](getting-started.html#storage-node).

### Tokens only

    [server]
    port = 443
    dir = "/data"
    metrics_address = "localhost:9100"

    [tls]
    enabled = true
    cert = "/etc/grid-security/hostcert.pem"
    key = "/etc/grid-security/hostkey.pem"

    [tokens]
    issuers = "/etc/weed/issuers.json"

    [tpc]
    enabled = true
    ca_path = "/etc/grid-security/certificates"

### Passwords, for a small site

    [server]
    port = 443
    dir = "/srv/dav"

    [tls]
    enabled = true
    cert = "/etc/pki/tls/certs/dav.example.org.pem"
    key = "/etc/pki/tls/private/dav.example.org.key"

    [basic]
    enabled = true
    htpasswd = "/etc/weed/htpasswd"
    app_tokens = "/etc/weed/app-tokens"

Basic credentials are sent in clear text without TLS: always enable \[tls\] with \[basic\].
