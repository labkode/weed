---
title: 'Logging'
---

weed logs to standard error, which systemd sends to the journal, or to `server.log_file`. Workers log through weed, so that everything is in one place. Log to a file, to keep every record (see [below](#file)):

    [server]
    log_file = "/var/log/weed/weed.log"
    log_level = "info"
    log_format = "text"

## A file keeps every record {#file}

The journal keeps so many lines of a service every 30 seconds, and drops the others until the 30 seconds are over: 10000 by default (RateLimitBurst= in journald.conf), a few times more on a disk with much free space. weed logs a record of every request, so a server that answers more than a few hundred a second loses records in the journal, and its errors with them: they reach the journal at the same priority as the requests. Of a service that wrote 25000 lines a second, as weed does answering 25000 requests a second, the journal kept those of the first 1.5 seconds, and dropped those of the next 8.5.

A file keeps them all. With the unit of [Installation](installation.html#systemd), systemd makes /var/log/weed (`LogsDirectory=weed`), which weed may write also when sandboxed. The record of a request takes some 270 bytes: 2.3 GB a day at 100 requests a second, 23 GB at 1000. Rotate the file (see [Rotation](#rotation)), keeping as many days as the disk allows. Writing the records costs weed little: some 4% of the requests it answers at 60000 a second, less at fewer.

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

    # grep request_id=869537c9 /var/log/weed/weed.log

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

    /var/log/weed/weed.log {
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

The reload also re-reads the credential files (see [Reloading](reloading.html)), which does no harm. Without `server.log_file`, the journal rotates the log itself, but does not keep every record (see [above](#file)):

    # journalctl -u weed -f
    # journalctl -u weed --since today -g 'level=ERROR'
