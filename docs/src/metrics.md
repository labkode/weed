---
title: 'Metrics'
---

weed serves these metrics at /metrics on `server.metrics_address`, in the Prometheus text format (see [Monitoring](monitoring.html)). The workers report theirs to weed, which serves the totals. Counters start at 0 when weed starts.

## Requests

| Metric | Type | Labels | Meaning |
|----|----|----|----|
| [`weed_http_requests_total`]{#weed_http_requests_total} | counter | method, code | HTTP requests to the main port, by method and status code. Methods other than those of HTTP and WebDAV are counted as "other". |
| [`weed_http_response_bytes_total`]{#weed_http_response_bytes_total} | counter | method | Bytes sent in response bodies, by method: the downloads are those of GET. |
| [`weed_upload_bytes_total`]{#weed_upload_bytes_total} | counter |  | Bytes stored by successful uploads (PUT). |
| [`weed_requests_in_progress`]{#weed_requests_in_progress} | gauge | kind | Authenticated WebDAV requests being served, by kind: download (GET), upload (PUT), tpc_pull and tpc_push (third-party copies, for as long as their COPY lasts), other (PROPFIND, MKCOL, DELETE, MOVE, local COPY, ...). /status also counts them by user. |
| [`weed_auth_requests_total`]{#weed_auth_requests_total} | counter | method, result | Authentication outcomes of WebDAV requests, by the method that decided them (x509, token, macaroon, basic, anonymous; none when no credentials were accepted) and result (success, forbidden, unauthorized). |
| [`weed_checksum_mismatches_total`]{#weed_checksum_mismatches_total} | counter | operation | Transfers refused because the data did not match the client's checksum, by operation (put, tpc_pull, tpc_push). |

## Third-party copy {#tpc}

| Metric | Type | Labels | Meaning |
|----|----|----|----|
| [`weed_tpc_transfers_total`]{#weed_tpc_transfers_total} | counter | mode, result | Finished third-party copies by mode (pull, push) and result (success, failure). |
| [`weed_tpc_bytes_total`]{#weed_tpc_bytes_total} | counter | mode | Bytes moved by third-party copies, by mode. |
| [`weed_tpc_active_transfers`]{#weed_tpc_active_transfers} | gauge | mode | Third-party copies in progress, by mode. |
| [`weed_tpc_rejected_total`]{#weed_tpc_rejected_total} | counter |  | Third-party copies refused (503) because `tpc.max_transfers` were already running. |

## Workers

| Metric | Type | Labels | Meaning |
|----|----|----|----|
| [`weed_workers`]{#weed_workers} | gauge |  | Worker processes, including those finishing requests after being replaced. |
| [`weed_worker_starts_total`]{#weed_worker_starts_total} | counter | result | Worker processes started, by result (success, failure). |
| [`weed_worker_exits_total`]{#weed_worker_exits_total} | counter | reason | Worker processes that exited, by reason: stopped when asked to (e.g. when idle), killed when their account was banned, failed otherwise. |
| [`weed_storage_unmounted`]{#weed_storage_unmounted} | gauge |  | 1 while the storage that the exported directory was on when weed started is not mounted: requests get 503 until it is again, never served from the directory beneath (see [Installation](installation.html#mounted)). |
| [`weed_worker_blocked_threads`]{#weed_worker_blocked_threads} | gauge |  | Threads of the worker processes that wait in the kernel, uninterruptibly: for a moment while they read or write files; for long while the storage does not answer, and then their requests do not end, nor do their workers exit, even when killed (see [Troubleshooting](troubleshooting.html#hung-storage)). |

## Network

| Metric | Type | Labels | Meaning |
|----|----|----|----|

## Credentials

| Metric | Type | Labels | Meaning |
|----|----|----|----|
| [`weed_crl_expiry_timestamp_seconds`]{#weed_crl_expiry_timestamp_seconds} | gauge |  | When the first CA runs out of current CRLs: with `x509.crl_mode = "require"`, its users are refused from then on. Absent without CRLs. |
| [`weed_tls_certificate_expiry_timestamp_seconds`]{#weed_tls_certificate_expiry_timestamp_seconds} | gauge |  | When the host certificate expires. Absent without TLS. |
| [`weed_reloads_total`]{#weed_reloads_total} | counter | result | Credential reloads by result: success, or partial when some file could not be read. |
| [`weed_reload_last_success_timestamp_seconds`]{#weed_reload_last_success_timestamp_seconds} | gauge |  | When credentials were last reloaded completely (or loaded at startup). |
| [`weed_reload_last_successful`]{#weed_reload_last_successful} | gauge |  | 1 if the last reload read every credential file, CA and certificate; 0 if some kept their previous contents. |
| [`weed_banned_users`]{#weed_banned_users} | gauge |  | Users that weed refuses whatever their credentials (`weed utils ban`). |

## What runs

| Metric | Type | Labels | Meaning |
|----|----|----|----|
| [`weed_build_info`]{#weed_build_info} | gauge | version, revision, modified, goversion, build | Always 1: the build of weed that runs (see [What runs](what-runs.html#version)). |
| [`weed_config_info`]{#weed_config_info} | gauge | file, sha256 | Always 1: the configuration file weed runs with, and the SHA-256 of its content when weed started (empty without a file). |
| [`weed_restart_pending`]{#weed_restart_pending} | gauge | reason | 1 if a restart would run something else than what runs: the configuration file (config) or the executable (binary) has changed since weed started. |
| [`process_start_time_seconds`]{#process_start_time_seconds} | gauge |  | When weed started, in seconds since the Unix epoch. |

## Example

    $ curl -s localhost:9100/metrics | grep -v '^#'
    weed_http_requests_total{method="COPY",code="202"} 1
    weed_http_requests_total{method="GET",code="200"} 3
    weed_http_requests_total{method="GET",code="403"} 1
    weed_http_requests_total{method="PROPFIND",code="207"} 2
    weed_http_requests_total{method="PUT",code="201"} 3
    ...
    weed_auth_requests_total{method="token",result="success"} 3
    weed_auth_requests_total{method="x509",result="forbidden"} 1
    weed_auth_requests_total{method="x509",result="success"} 15
    weed_upload_bytes_total 1384703
    weed_tpc_transfers_total{mode="pull",result="success"} 1
    weed_tpc_bytes_total{mode="pull"} 692252
    weed_tpc_active_transfers{mode="pull"} 0
    weed_requests_in_progress{kind="download"} 0
    weed_requests_in_progress{kind="other"} 0
    weed_requests_in_progress{kind="tpc_pull"} 0
    weed_requests_in_progress{kind="tpc_push"} 0
    weed_requests_in_progress{kind="upload"} 0
    weed_workers 2
    weed_worker_starts_total{result="success"} 3
    weed_worker_exits_total{reason="stopped"} 1
    weed_crl_expiry_timestamp_seconds 1.793869616e+09
    weed_tls_certificate_expiry_timestamp_seconds 1.795856816e+09
    process_start_time_seconds 1.793264817406e+09
    weed_build_info{version="v1.2.0",revision="46a37813bc81d7a1b9a8b1e2a9e1f3c3e6c2a0d4",modified="false",goversion="go1.27.3",build="go:2CX-x4_-..."} 1
    weed_config_info{file="/etc/weed/weed.toml",sha256="6794c30b95c0972e5a032630bb90ccdf474c3df01a9dd983f88c9fdc5baf417e"} 1
    weed_restart_pending{reason="config"} 0
    weed_restart_pending{reason="binary"} 0
    weed_reload_last_success_timestamp_seconds 1.793264817406e+09
    weed_reload_last_successful 1
    weed_banned_users 0
    weed_storage_unmounted 0
    weed_worker_blocked_threads 0

Series of a counter appear once something has been counted; weed_requests_in_progress and weed_restart_pending have every series from the start.
