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
- A symbolic link that leads outside the exported directory, and every absolute one,
  gets 403 and is left out of listings (see Fixed).
- When the storage that weed started on is no longer mounted, weed refuses requests
  with 503, /healthz too, rather than serve the directory beneath; when a storage is
  mounted again over the exported directory, weed exits with status 75, for its
  supervisor to start it again.
- weed listens with TCP, not with MPTCP, which Go listened with where the kernel has
  it. Clients with MPTCP fall back to TCP.

### New

- seccomp: weed opens Unix, netlink, TCP and UDP sockets alone, and its workers Unix
  sockets alone (as weed with tpc.enabled), and neither has io_uring.
- server.require_mount refuses to start while the exported directory is on the file
  system of /.
- weed serves on the sockets that systemd passes (socket activation), and the guide's
  systemd unit restarts it with a backoff that never gives up.
- /status's storage_unmounted and the metric weed_storage_unmounted.
- Releases, with this changelog, and the version that the guide is for in its header.

### Fixed

- Workers could open MPTCP, SCTP and other sockets that the rules of TCP of Landlock
  do not cover, and bind and connect with them where the rules refuse it.
- Symbolic links led outside the exported directory: a user who can make links in it
  could have weed read and write whatever their account can.
