---
title: 'Third-party copy'
---

A third-party copy (TPC) moves a file between two storage endpoints directly, without passing through the client that asks for it. FTS, Rucio and gfal-copy use it between sites. weed implements WLCG HTTP-TPC in both directions, pull and push, with the data-integrity extension: checksums are verified end to end.

    [tpc]
    enabled = true
    ca_path = "/etc/grid-security/certificates"

## How a copy works {#how}

The endpoint that receives the COPY request is the active party: it performs the transfer itself, as the account of the client.

Pull: COPY with a Source header
:   weed GETs the remote file and stores it at the request's path.

Push: COPY with a Destination on another server
:   weed PUTs the local file to the remote URL.

Headers named TransferHeader\<Name\> are forwarded to the remote as \<Name\>. That is how the client passes the remote endpoint's credentials, typically a token or a macaroon in TransferHeaderAuthorization. weed does not delegate X.509 credentials (Credential: gridsite).

    $ curl --cert alice.pem --key alice.key -X COPY \
        -H 'Source: https://other.example.org/webdav/data/big' \
        -H "TransferHeaderAuthorization: Bearer $MACAROON" \
        -H 'Repr-Digest: adler=:Qm6Eiw==:' \
        https://weed.example.org/webdav/alice/big

weed answers 202 at once, with a text/perf-marker-stream body. It sends a performance marker every `tpc.marker_interval` (5s by default), and ends with a status line:

    Perf Marker
        Timestamp: 1793265010
        Stripe Index: 0
        Stripe Bytes Transferred: 208404480
        Total Stripe Count: 1
        RemoteConnections: tcp:203.0.113.9:443
    End
    ...
    success: Created

A failed copy ends with "failure: \<reason\>". With gfal2, `gfal-copy --copy-mode pull` (or push) asks for a third-party copy; FTS chooses itself. With tokens, the client passes one token for weed (Authorization) and one for the remote (TransferHeaderAuthorization); gfal2 does this with BEARER_TOKEN set.

## Checksums {#integrity}

- A pull with a Repr-Digest asks the source for a digest of the same algorithms (Want-Repr-Digest). If the source's digest contradicts the client's, the copy fails before any data is stored. Whatever the source says, weed checksums the bytes it receives, and compares them with the client's Repr-Digest. On a mismatch, the file is not stored, and the stream ends with "failure: file not saved: client/server checksum mismatch ...".
- A push forwards Repr-Digest on its PUT. A 412 from the destination is reported as "client/server checksum mismatch reported by destination".
- A source whose answer has neither a Content-Length nor chunked framing, or has a Content-Encoding, or stalls for `tpc.stall_timeout` (2m), fails the copy.

A pull is written as any upload is: to a hidden file, renamed into place only when complete and verified (see [Storage](storage.html)).

## Limits

At most `tpc.max_transfers` (32) copies run at once, for all accounts together. More get 503, with Retry-After, and are counted in `weed_tpc_rejected_total`. `weed_tpc_active_transfers` counts the copies running, by mode, and `weed_requests_in_progress` the COPY requests in progress (see [Metrics](metrics.html)).

Errors found before any transfer starts are answered at once:

| Status | When |
|----|----|
| 400 | a bad Source or Destination, or one with another scheme than https |
| 404, 405 | a push of a file that does not exist, or of a directory |
| 405 | a pull onto a directory |
| 409 | the parent directory does not exist |
| 412 | Overwrite: F onto an existing file |
| 423 | the target is locked |
| 501 | TPC is disabled, or credential delegation was asked for (only Credential: none is supported) |
| 503 | `tpc.max_transfers` copies are running |

## Remote endpoints

A COPY makes weed connect wherever its client says. So that it cannot be used to reach the services inside your site, weed checks every address that a remote endpoint resolves to, when it connects and after every redirect:

- Remote endpoints must be https://, unless `tpc.allow_http`.
- Loopback, link-local and multicast addresses, and 0.0.0.0/8, are refused unless `tpc.allow_local` (for tests only).
- Private addresses (RFC 1918, fc00::/7), shared addresses (100.64.0.0/10), the other special-purpose ranges of RFC 6890, and IPv6 addresses that embed IPv4 ones (NAT64, 6to4, Teredo) are refused unless `tpc.allow_private`. IPv4-mapped IPv6 addresses count as IPv4.
- The unspecified address is always refused.

If your storage endpoints talk over a private network, set `tpc.allow_private`, and protect the services on that network otherwise. weed follows at most 10 redirects, never to http:// when that is not allowed, and never one that changes the method.

weed verifies remote endpoints with the system's CAs, and those of `tpc.ca_path`: set it to /etc/grid-security/certificates to trust the IGTF CAs. Workers re-read it on reload (see [Reloading](reloading.html)), so the users must be able to read it.
