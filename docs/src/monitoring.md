---
title: 'Monitoring'
---

weed serves Prometheus metrics at /metrics, what runs at /status, a dashboard of both at /, and a health check at /healthz, on `server.metrics_address`:

    [server]
    metrics_address = "localhost:9100"

These endpoints have no authentication. /status shows the configuration (secrets redacted) and the names of the users with requests in progress, so serve them on localhost, or on an address that only your monitoring reaches. Without a configuration file, they are on the main port, whose clients are local (the dashboard at /dashboard/).

## The dashboard {#dashboard}

http://localhost:9100/ is a page that your browser fills from /status and /metrics every 2 seconds, and that changes nothing:

- tiles: egress and ingress now; requests per second, with the 4xx and 5xx; requests in progress, by kind; workers and their blocked threads; third-party copies; banned users;
- charts of the last 10 minutes, kept by the browser while the page is open: throughput; requests per second, by status; requests in progress, by kind;
- the accounts with workers or requests in progress: their workers, their requests in progress and of which kind, and their blocked threads. Click a column to sort by it;
- the workers, their requests and how long they have run; the outcomes of authentication, by method; the build and the configuration;
- warnings: a pending restart, a partial reload, blocked threads, a TLS certificate or CRLs about to expire, and weed not answering.

It needs no other software, and loads nothing from elsewhere. weed counts the bytes of a transfer when it ends, so the charts of rates average over 10 seconds, and a long transfer counts when it ends. For history beyond the page, scrape /metrics with Prometheus (see below).

## /healthz

/healthz answers "ok" (200) when the exported directory responds, and 503 when it does not, or not within 5 seconds: a hung network filesystem otherwise shows only as hanging requests. It answers 503 too while the storage of the exported directory is not mounted (see [Installation](installation.html#mounted)). It is also on the main port, for load balancers. While the directory does not answer, weed looks at it again only once the look in progress has returned, however often /healthz is called: each look waits in the kernel with a thread of weed's, until the storage answers.

    $ curl -s https://weed.example.org/healthz
    ok

## /status

/status tells, as JSON, which build runs and since when, with which configuration, how the last reload went, whether a restart is pending, the workers, and the requests in progress. It is what to look at first when something is odd. (See also [What runs](what-runs.html).)

    $ curl -s localhost:9100/status | jq .
    {
      "version": {
        "version": "v1.2.0",
        "revision": "46a37813bc81d7a1b9a8b1e2a9e1f3c3e6c2a0d4",
        "time": "2026-10-28T16:07:11Z",
        "modified": false,
        "go": "go1.27.3",
        "platform": "linux/amd64",
        "build": "go:2CX-x4_-THjPR2Dy4JCE/TtMef8lUxfkIJsGhiXwh/3-NbDYhNvYZpdojQpjfp/Dg3..."
      },
      "pid": 95,
      "started": "2026-10-29T09:06:57.406698793Z",
      "uptime": "2h13m5s",
      "config": {
        "file": "/etc/weed/weed.toml",
        "sha256": "6794c30b95c0972e5a032630bb90ccdf474c3df01a9dd983f88c9fdc5baf417e",
        "settings": {
          "admin": {
            "bans": "/var/lib/weed/bans.json",
            "socket": "/run/weed/admin.sock"
          },
          ...
          "macaroons": {
            "enabled": true,
            "location": "weed-webdav",
            "max_validity": "24h",
            "secret_key": "<redacted>"
          },
          ...
        }
      },
      "reload": {
        "last": "2026-10-29T11:06:57.411236512Z",
        "last_success": "2026-10-29T11:06:57.411236512Z",
        "successful": true
      },
      "restart_pending": {},
      "workers": [
        {
          "account": "alice",
          "uid": 1001,
          "pid": 127,
          "started": "2026-10-29T09:06:57.546247626Z",
          "requests": 1,
          "retired": false,
          "blocked_threads": 0
        },
        {
          "account": "cms001",
          "uid": 2001,
          "pid": 166,
          "started": "2026-10-29T09:06:57.874668126Z",
          "requests": 3,
          "retired": false,
          "blocked_threads": 0
        }
      ],
      "banned_users": 0,
      "in_progress": {
        "total": {
          "download": 1,
          "other": 0,
          "tpc_pull": 2,
          "tpc_push": 0,
          "upload": 1
        },
        "by_user": {
          "alice": {
            "download": 1
          },
          "cms001": {
            "tpc_pull": 2,
            "upload": 1
          }
        }
      }
    }

reload
:   the last reload (absent if none since startup), the last complete one, and whether the last read everything (see [Reloading](reloading.html)).

restart_pending
:   why a restart would change what runs, by reason: config, binary. Empty when nothing would change.

storage_unmounted
:   since when the storage that the exported directory was on is not mounted, absent while it is: requests get 503 (see [Installation](installation.html#mounted)).

workers
:   each worker: its account, its pid, since when it runs, and how many requests weed waits for it to answer. A retired worker finishes its requests and takes no new ones, e.g. after its account's groups changed. blocked_threads are the worker's threads that wait in the kernel, uninterruptibly: for a moment while they read or write files, and for long when its storage does not answer, also once their clients have gone (see [Troubleshooting](troubleshooting.html#hung-storage)).

## Transfers in progress {#in-progress}

`in_progress` counts the authenticated WebDAV requests being served, by kind, in total and by user:

| Kind               | Requests                                            |
|--------------------|-----------------------------------------------------|
| download           | GET                                                 |
| upload             | PUT                                                 |
| tpc_pull, tpc_push | third-party copies, for as long as their COPY lasts |
| other              | PROPFIND, MKCOL, DELETE, MOVE, local COPY, ...      |

The metric `weed_requests_in_progress{kind}` counts the same totals. Before a restart, check that no long transfer would be cut:

    # curl -s localhost:9100/status | jq .in_progress.total
    # curl -s localhost:9100/status | jq '.in_progress.by_user | to_entries[] | select(.value.tpc_pull)'

## Prometheus

    scrape_configs:
      - job_name: weed
        static_configs:
          - targets: ["weed.example.org:9100"]

With `metrics_address = "localhost:9100"`, scrape it from the host, e.g. through node_exporter's or your agent's local scraping, or listen on an address of the management network instead. [Metrics](metrics.html) lists every metric.

## What to alert on {#alerts}

| Alert | Expression |
|----|----|
| weed is down | `up{job="weed"} == 0`, or /healthz failing from outside |
| the storage is not mounted | `weed_storage_unmounted == 1` |
| CRLs about to expire (fetch-crl stopped) | `weed_crl_expiry_timestamp_seconds - time() < 6 * 3600` |
| host certificate about to expire | `weed_tls_certificate_expiry_timestamp_seconds - time() < 14 * 86400` |
| a credential file cannot be read | `weed_reload_last_successful == 0` |
| a restart has been pending for a day | `weed_restart_pending == 1`, for 1d |
| servers run different builds | `count(count by (build) (weed_build_info)) > 1` |
| workers cannot start | `increase(weed_worker_starts_total{result="failure"}[10m]) > 0` |
| workers fail | `increase(weed_worker_exits_total{reason="failed"}[10m]) > 0` |
| too many workers (raise unix_users.max_workers) | `weed_workers > 0.9 * 256` |
| third-party copies refused (raise tpc.max_transfers) | `increase(weed_tpc_rejected_total[1h]) > 0` |
| third-party copies failing | `rate(weed_tpc_transfers_total{result="failure"}[1h]) / rate(weed_tpc_transfers_total[1h]) > 0.1` |
| server errors | `sum(rate(weed_http_requests_total{code=~"5.."}[5m])) / sum(rate(weed_http_requests_total[5m])) > 0.05` |
