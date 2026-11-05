---
title: 'Upgrading'
---

A new version of weed runs once weed restarts. Until then, weed and its workers keep running the binary they started with, and weed says that a restart is pending. Before upgrading, read the [Changelog](changelog.html) from your version to the new one: the Incompatible changes of each version say what to change first.

## Versions {#versions}

weed's versions are numbered MAJOR.MINOR.PATCH, as in [Semantic Versioning](https://semver.org), and released on [GitHub](https://github.com/labkode/weed/releases) (see [Installation](installation.html#releases)):

- A new PATCH fixes bugs, and changes nothing else.
- A new MINOR adds what the version before did not have, such as options, metrics, fields of /status or commands, and keeps what that version did with the same configuration.
- A new MAJOR has incompatible changes, which the changelog lists first in its section.

A change is incompatible if a server, or what watches it, may stop working as it did with the same configuration, files and clients:

- An option or a section that is removed or renamed, or whose default or meaning changes: weed refuses an option that it does not know.
- A file that weed reads or writes in another format: the configuration, the limits of unix_users.limits, app tokens, the bans file, the grid-mapfile, the stored checksums.
- What weed needs to run: Linux, its version and its security modules, the architectures, what the guide's systemd unit gives it.
- A metric, a label or a field of /status that is removed or renamed, or whose meaning changes.
- A command, a flag, an exit status or an output that scripts read, such as that of *weed utils bans*.
- What clients see: the URLs, the status codes and headers of requests that worked, the authentication methods, the checksums.

What weed logs, the dashboard, and how weed talks to its workers (always of the same build) may change in any version.

Between releases, the main branch is the development version, which the header of its guide says: its changes, incompatible ones too, are in the changelog's Unreleased section.

## Upgrading {#procedure}

1.  Get the new version (see [Installation](installation.html#releases)), or build it, and look at what it is:

        $ make build && ./weed version

2.  Install it by replacing the file: the RPM's *dnf upgrade* does, which does not restart weed, as *install* and *mv* do. (Linux refuses to write into a binary that runs: *cp* onto it fails with "Text file busy".)

        # dnf upgrade https://github.com/labkode/weed/releases/download/v1.3.0/weed-1.3.0-1.el10.x86_64.rpm

    or, without the RPM:

        # install -m 0755 weed /usr/local/bin/weed

    weed now logs that a restart is pending, with the new version:

        level=WARN msg="restart pending: weed's executable /usr/local/bin/weed is now v1.3.0 (commit 9c1e0a2b77d4 of ...) go1.27.3 linux/amd64, build go:..." reason=binary

3.  Check that the new version starts with your configuration. The new version may know options that the old one did not, or warn about others. The RPM's *dnf upgrade* does it, and says how it went (see [Installation](installation.html#rpm)); otherwise:

        # weed check -config /etc/weed/weed.toml
        /etc/weed/weed.toml: weed would start with it (sha256 6794c30b95c0...), as the account weed too (User= of weed.service)

    Run by root, it checks as the account weed too, which may not read every file that root reads (see [Commands](commands.html#check)).

4.  Restart, when the transfers in progress allow it (see [Monitoring](monitoring.html#in-progress)):

        # curl -s localhost:9100/status | jq .in_progress.total
        # systemctl restart weed

    weed gives the requests in progress 30 seconds to finish.

5.  Check what runs:

        # systemctl status weed
        # curl -s localhost:9100/status | jq '.version.version, .restart_pending'

## Until the restart {#old-binary}

Workers are started from /proc/self/exe, which is the binary that weed started from, even after it has been replaced on disk. So weed and every worker it starts run the same build. `ls -l /proc/<pid>/exe` shows the old binary as deleted, for weed and its workers alike.

Each worker also reports its build, which weed compares with its own. Should the binary's content change without the file being replaced, new workers would run the new code, so weed refuses them: requests that need a new worker get 503, and weed logs "cannot start a worker" with both builds, until it is restarted.

## Several servers

Upgrade one server at a time, and watch `weed_build_info`: when every server runs the new build, `count(count by (build) (weed_build_info))` is 1 again. Macaroons stay valid across servers and restarts as long as `macaroons.secret_key` is the same.
