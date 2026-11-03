# Changelog

The changes of each version of weed, the newest first. Versions are numbered
MAJOR.MINOR.PATCH, as in Semantic Versioning: a version with a new MAJOR number is not
compatible with the one before it, and its section begins with Incompatible changes,
what to change before upgrading to it. The guide's Upgrading page says what counts as
incompatible.

## Unreleased

The first release. weed serves files over HTTP and WebDAV to the clients and services
of the WLCG (gfal2, davix, FTS, Rucio, XRootD): authentication with X.509 certificates
and proxies, WLCG and SciTokens tokens, macaroons, an OIDC login page and passwords;
third-party copies in both directions; checksums from end to end; each request served
as the Unix account that its credentials map to, by a worker process confined with
Landlock and seccomp; cgroup limits per user and group; bans; metrics, /status and a
dashboard.

Until now, weed was built from the main branch. For a server that ran a build of it
from 2026-10-29 or later, when the administration guide came, these are the changes.

### Incompatible changes

- weed builds and runs on Linux alone, on amd64 and arm64: weed utils, config, check
  and version no longer build for other systems, and weed no longer serves on macOS
  for development.
- weed needs Linux 5.19 or later with landlock among the security modules (lsm=), and
  seccomp: it confines itself and its workers, and does not start otherwise.
  unix_users.landlock is gone: a configuration that sets it is refused.
- weed's own process, which terminates TLS and authenticates requests, is confined
  with Landlock: it writes only the exported directory, the directories of
  admin.socket and admin.bans, its cgroup and its log file, and binds only its ports.
  weed does not export /.
- Network rate limits are gone: the [network] section (egress_rate, ingress_rate,
  account_egress_rate, account_ingress_rate), the rates in the file of
  unix_users.limits, which weed now refuses, /status's network and the metric
  weed_network_delay_seconds_total. The kernel paces transfers, with tc (see the
  guide's Limits per account).
- weed follows no symbolic link beneath the exported directory, wherever it points: a
  name with a link in it gets 403, and links are left out of listings (see Fixed).
  Links that stayed inside were followed: put what they point to in their place, or
  bind-mount it there. Workers open files with openat2(2), and refuse to serve where a
  seccomp filter refuses it.
- When the storage that weed started on is no longer mounted, weed refuses requests
  with 503, /healthz too, rather than serve the directory beneath; when a storage is
  mounted again over the exported directory, weed exits with status 75, for its
  supervisor to start it again.
- weed listens with TCP, not with MPTCP, which Go listened with where the kernel has
  it. Clients with MPTCP fall back to TCP.
- The content type of a file, GET's Content-Type and PROPFIND's getcontenttype, comes
  from its name's extension alone, and is application/octet-stream when the system's
  MIME types (shared-mime-info or /etc/mime.types) and Go's do not know it: weed no
  longer reads the first 512 bytes of a file to guess it.

### New

- seccomp: weed opens Unix, netlink, TCP and UDP sockets alone, and its workers Unix
  sockets alone (as weed with tpc.enabled), and neither has io_uring.
- server.require_mount refuses to start while the exported directory is on the file
  system of /.
- weed serves on the sockets that systemd passes (socket activation), and the guide's
  systemd unit restarts it with a backoff that never gives up.
- /status's storage_unmounted and the metric weed_storage_unmounted.
- Releases, with this changelog, and the version that the guide is for in its header.
- weed answers PROPFIND, GET and HEAD itself, rather than golang.org/x/net/webdav:
  PROPFIND from the metadata of a stat and a listing (getdents64, then statx), without
  opening any file, nor allocating for each entry. A worker spends about 0.3 ms of CPU
  on a Depth 1 PROPFIND of 100 files, from 3.2 ms, and its listing halves that again.
  On a laptop of 12 cores, weed answers 25000 of them a second, and 5000 of a
  directory of 1000 files.
- PROPFIND's include, with allprop, which x/net/webdav ignored.
- unix_users.max_storage_calls (default 256) bounds the calls to the storage in
  progress at once in each worker, and so its threads: the requests beyond wait for
  one to end without a thread, and stop waiting when their client goes.
- The guide's Performance page: what limits each kind of request, which settings of
  weed, systemd and the kernel to change, and how to measure a server. The guide's
  systemd unit sets TasksMax=infinity: systemd's default, 15% of kernel.threads-max,
  is fewer than the threads that weed's workers hold when the storage stops
  answering, on a machine of less than about 64 GB of memory.

### Fixed

- Workers could open MPTCP, SCTP and other sockets that the rules of TCP of Landlock
  do not cover, and bind and connect with them where the rules refuse it.
- Symbolic links led outside the exported directory: a user who can make links in it
  could have weed read and write whatever their account can. And a link in a
  directory took a macaroon or token for that directory to wherever it points.
- A file could not be read through a directory that the account may search but not
  read (such as one of mode 711), nor uploaded to a directory that it may write and
  search but not read: weed now asks of directories what the kernel does.
- GET or HEAD of a FIFO in the exported directory, a COPY or third-party push of one,
  and a PROPFIND of Depth 1 of its directory, waited for a writer to open it, forever.
  A FIFO gets 405 to GET, as directories do, and 403 to COPY.
- A worker serving thousands of requests at once made a thread for each, which Go
  never gives back, and died, its requests with 502, when its cgroup's pids.max
  refused one more: Podman's default of 2048, for one, at some 2000 clients listing
  directories at once. Its threads are now bounded by unix_users.max_storage_calls:
  serving 8192 clients, a worker had 8559 threads, and now has 285.
