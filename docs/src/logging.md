---
title: 'Logging'
---

weed logs to standard error, which systemd sends to the journal, or to `server.log_file`. Workers log through weed, so that everything is in one place.

    [server]
    log_file = "/var/log/weed.log"
    log_level = "info"
    log_format = "text"

## Format

One record per line: key=value (`log_format = "text"`), or JSON (`"json"`) for a log collector. The records are the same; JSON nests the attributes that text joins with dots.

    time=2026-10-29T09:06:57.571Z level=INFO msg=request method=PUT path=/webdav/alice/hosts proto=HTTP/1.1 status=201 bytes=0 duration=27.850916ms user=alice remote=192.0.2.7:43784 user_agent=curl/7.76.1 request_id=ea9b00ce

    {"time":"2026-10-29T09:10:09.954448632Z","level":"INFO","msg":"third-party copy started","worker":{"user":"alice","pid":203},"mode":"pull","local":"/data/alice/big.copy","remote":"https://other.example.org/webdav/data/big","request_id":"32c0a9dc"}

Errors found before the configuration is read, such as a configuration file that does not exist, are logged in Go's default format:

    2026/10/29 09:10:12 ERROR cannot read the configuration error="open /etc/weed/weed.toml: no such file or directory"

When weed cannot start, it also writes why to standard error, even when it logs to a file, so that the journal and the terminal show it:

    weed: cannot start: failed to load the grid-mapfile: open /etc/grid-security/grid-mapfile: no such file or directory

## Levels

error
:   something is wrong and needs you: weed cannot start or serve, a worker cannot start or failed, the bans cannot be saved, weed would not start with the configuration file. Requests that panicked.

warn
:   something to know: a file that a reload could not read, a restart pending, a ban or its lifting, a failed third-party copy, an upload that did not match its checksum, a request without a worker (503), a configuration that is risky (no CRLs, no TLS, anonymous requests).

info (the default)
:   what weed loaded and how it is set up, every request, every refused credential and why, third-party copies, workers starting and stopping.

debug
:   how each request was authenticated, and which methods were tried. For finding a problem, not for every day.

## Requests

Every request to the main port is logged once, when it ends, as a "request" record:

| Attribute | Meaning |
|----|----|
| method, path, proto | the request |
| status, bytes | the status code, and the bytes of the response body |
| duration | from the request to the end of the response |
| user | the user that the credentials map to, also when the request was refused with 403; nobody for requests without credentials, or with credentials that were refused with 401 |
| remote, user_agent | the client |
| request_id | the request's ID, which every record that weed and its worker log for the request also carries |
| aborted, panic | if the request ended abnormally: the client went away (aborted), or the handler panicked (at error) |

To follow one request, look for its ID:

    # grep request_id=869537c9 /var/log/weed.log

A third-party copy is a single COPY request, logged when it ends, which may be hours after it started. Its "third-party copy started" and "third-party copy completed" (or "failed") records say what was copied, how many bytes, and how long it took.

## Refused credentials {#authentication}

Every credential that weed refuses is logged at info, as "authentication failed", with the method and why. The request's record follows, with the same request_id:

    level=INFO msg="authentication failed" method=token error="forbidden: the token's scopes do not allow this request on /webdav/cms/hosts" request_id=a02c0ec1
    level=INFO msg=request method=PUT path=/webdav/cms/hosts proto=HTTP/1.1 status=403 bytes=10 duration=151.25µs user=cms001 remote=192.0.2.7:52494 user_agent=curl/7.76.1 request_id=a02c0ec1

[Troubleshooting](troubleshooting.html#refused) lists the reasons.

## Workers

The records of workers carry worker.user and worker.pid, and the request_id of the request they serve:

    level=INFO msg="started a worker" worker.user=alice worker.pid=127 account.name=alice account.uid=1001 account.gid=1001 account.groups=[1001]
    level=INFO msg="worker stopped" worker.user=alice worker.pid=127

## Rotation

On SIGHUP, weed reopens its log file. With logrotate, /etc/logrotate.d/weed:

    /var/log/weed.log {
        daily
        rotate 30
        compress
        delaycompress
        missingok
        notifempty
        postrotate
            systemctl reload weed >/dev/null 2>&1 || true
        endscript
    }

The reload also re-reads the credential files (see [Reloading](reloading.html)), which does no harm. Without `server.log_file`, the journal rotates the log itself:

    # journalctl -u weed -f
    # journalctl -u weed --since today -g 'level=ERROR'
