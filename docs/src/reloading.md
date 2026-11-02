---
title: 'Reloading'
---

Credentials change while weed runs: fetch-crl replaces CRLs, the grid-mapfile gets new users, the host certificate is renewed. weed re-reads them without a restart, on SIGHUP and every `server.reload_interval` (default 1h; "0s" reloads on SIGHUP only).

    # systemctl reload weed

With the unit of [Installation](installation.html#systemd), that sends SIGHUP and returns once the reload is done. Without systemd, `kill -HUP $(pidof -s weed)` does the same (weed ignores the SIGHUP that reaches its workers).

## What is reloaded {#what}

- the htpasswd and app tokens files;
- the grid-mapfile;
- the CAs and CRLs of client certificates;
- the token issuers file, and the CAs used to fetch their keys;
- the host certificate and key;
- the CAs of third-party copy endpoints, which the workers also re-read;
- Unix accounts, which are looked up again;
- the limits file, whose cgroup limits apply at once to the accounts that have workers (see [Limits per account](limits.html)).

The configuration file is not: it is read only at startup, and weed says when it has changed (see [What runs](what-runs.html#restart-pending)). Neither are the banned users, which are weed's own (see [Banning users](banning.html)). On SIGHUP, weed also reopens its log file.

A file that cannot be read keeps its previous contents, so a file in the middle of being rewritten neither locks everybody out nor lets anybody in. Such a reload is partial: it is logged as a warning, counted in `weed_reloads_total{result="partial"}`, and `weed_reload_last_successful` is 0 until a reload reads everything. New connections and requests use what was read; established ones are not affected.

    level=INFO msg="reloading credentials"
    level=INFO msg="loaded grid-mapfile" file=/etc/grid-security/grid-mapfile entries=2
    level=INFO msg="loaded CA certificates" path=/etc/grid-security/certificates certificates=1
    level=INFO msg="loaded CRLs" path=/etc/grid-security/certificates crls=1 mode=require
    level=INFO msg="loaded token issuers" file=/etc/weed/issuers.json issuers=1

## Adding and removing users {#gridmap}

Edit the grid-mapfile, the issuers file or the htpasswd file, and reload. Removing a DN from the grid-mapfile revokes that certificate's access at the next reload. To stop a user at once, whatever their credentials, ban them instead (see [Banning users](banning.html)).

## CRLs

fetch-crl keeps the CRLs current in /etc/grid-security/certificates. Reload weed after it runs, so that new CRLs apply before the old ones expire. With the default `x509.crl_mode = "require"`, a certificate whose CA has no current CRL is refused:

    level=INFO msg="authentication failed" method=x509 error="no current CRL from \"/DC=org/DC=example/CN=Example Grid CA\" to check \"/DC=org/DC=example/OU=Users/CN=Alice Smith\" against" request_id=5bb0022b

The reload interval (1h) picks new CRLs up anyway. To reload as soon as fetch-crl has run, add to its service a drop-in, /etc/systemd/system/fetch-crl.service.d/weed.conf:

    [Service]
    ExecStartPost=-/usr/bin/systemctl reload weed

Alert on `weed_crl_expiry_timestamp_seconds`, the time at which the first CA runs out of current CRLs: if fetch-crl stops working, that time arrives.

    weed_crl_expiry_timestamp_seconds - time() < 6 * 3600

## The host certificate {#certificate}

Replace /etc/grid-security/hostcert.pem and hostkey.pem, and reload: new connections use the new certificate. Alert on `weed_tls_certificate_expiry_timestamp_seconds` before it expires.
