---
title: 'Upgrading'
---

A new version of weed runs once weed restarts. Until then, weed and its workers keep running the binary they started with, and weed says that a restart is pending.

## Upgrading {#procedure}

1.  Build the new version, and look at what it is:

        $ make build && ./weed version

2.  Install it by replacing the file: *install* and *mv* do, as package managers do. (Linux refuses to write into a binary that runs: *cp* onto it fails with "Text file busy".)

        # install -m 0755 weed /usr/local/bin/weed

    weed now logs that a restart is pending, with the new version:

        level=WARN msg="restart pending: weed's executable /usr/local/bin/weed is now v1.3.0 (commit 9c1e0a2b77d4 of ...) go1.27.3 linux/amd64, build go:..." reason=binary

3.  Check that the new version starts with your configuration. The new version may know options that the old one did not, or warn about others:

        # weed check -config /etc/weed/weed.toml
        /etc/weed/weed.toml: weed would start with it (sha256 6794c30b95c0...)

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
