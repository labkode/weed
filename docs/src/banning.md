---
title: 'Banning users'
---

A banned user is refused, with 403, whatever their credentials: certificate, token, macaroon or password. Banning a user stops their worker processes at once, which ends their requests and third-party copies in progress. Use it when credentials are compromised or a user misbehaves, before you have time to fix the grid-mapfile, the issuer or the htpasswd file.

## Banning and lifting a ban {#commands}

    # weed utils ban -reason 'compromised credentials' alice
    banned alice; stopped its 1 worker process(es)
    # weed utils bans
    USER   SINCE                    BY              REASON
    alice  2026-10-29 09:06:57 UTC  uid 0, pid 203  compromised credentials
    # weed utils unban alice
    lifted the ban of alice

The user is the name that credentials map to, which is the Unix account (see [Unix accounts](unix-accounts.html)): the account in the grid-mapfile, the user of an issuer's rule, the htpasswd user. Banning nobody refuses anonymous requests.

From then on, the user's requests get 403, and so does their OIDC login. Their macaroons, which carry their name, are refused too. The log says it:

    level=WARN msg="user banned" user=alice reason="compromised credentials" by="uid 0, pid 203" workers_killed=1
    level=INFO msg=request method=GET path=/webdav/alice/hosts proto=HTTP/1.1 status=403 bytes=10 duration=153.458µs user=alice remote=192.0.2.7:43898 user_agent=curl/7.76.1 request_id=595f7658
    level=WARN msg="ban lifted" user=alice by="uid 0, pid 220"

Banning a user who is banned already keeps the first ban, and stops any worker that a request started since.

## Across restarts {#persistence}

Bans are kept in `admin.bans` (/var/lib/weed/bans.json), which weed writes at every change, and reads at startup. They are weed's own state, not configuration: weed does not re-read the file on reload, and you should not edit it while weed runs. `admin.bans = ""` keeps bans in memory only, until weed stops.

If weed cannot save the file, the ban still applies until weed stops, and weed utils says so and exits with 1:

    banned alice; stopped its 1 worker process(es)
    weed utils: the ban lasts only until weed stops: ...

weed does not start if it cannot read the file, rather than start without the bans.

## The control plane {#control-plane}

weed utils ban, unban and bans talk to the running weed through its control plane, a Unix socket at `admin.socket` (/run/weed/admin.sock). Only root and weed's own user can use it: weed creates the socket with mode 0600, in a directory only its owner may enter, and checks the user of every connection. weed utils finds the socket with `-config` (the configuration file that weed runs with) or `-socket`; without either, it is the default one.

    # weed utils bans -config /etc/weed/weed.toml

If weed is not running, or another user tries:

    weed utils: cannot reach weed's control plane at /run/weed/admin.sock (is weed running there? -socket or -config names another): dial unix /run/weed/admin.sock: connect: permission denied

Two weeds cannot share a socket: the second refuses to start ("control plane: /run/weed/admin.sock is in use, by another weed?"). Give each its own `admin.socket`. `admin.socket = ""` disables the control plane.

### The API {#api}

The control plane is HTTP with JSON over the socket, which scripts can use directly. Operations are versioned, under /v1/:

| Request | Answer |
|----|----|
| GET /v1/bans | `{"bans": [{"user", "since", "reason", "by"}, ...]}` |
| PUT /v1/bans/{user}, with an optional body `{"reason": "..."}` | `{"user", "since", "reason", "by", "added", "workers_killed", "warning"}`; added is false if the user was banned already |
| DELETE /v1/bans/{user} | `{"user", "removed", "warning"}`; removed is false if the user was not banned |

Errors are answered with a status code and `{"error": "..."}`. An operation that the running weed does not know gets 404, e.g. from a weed older than weed utils.

    # curl -s --unix-socket /run/weed/admin.sock -X PUT -d '{"reason":"abuse"}' http://weed/v1/bans/alice
    {"user":"alice","since":"2026-10-29T09:06:57Z","reason":"abuse","by":"uid 0, pid 812","added":true,"workers_killed":1}
    # weed utils bans -json
    {
      "bans": [
        {
          "user": "alice",
          "since": "2026-10-29T09:06:57Z",
          "reason": "abuse",
          "by": "uid 0, pid 812"
        }
      ]
    }

The metric `weed_banned_users` counts the banned users, and /status says how many there are.
