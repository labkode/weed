---
title: 'Storage and checksums'
---

weed serves `server.dir` under /webdav/: the file /data/alice/hosts is https://weed.example.org/webdav/alice/hosts. It keeps nothing of its own next to the files, except checksums in extended attributes.

## What weed guarantees {#guarantees}

- Uploads (PUT, local COPY, TPC pull) are written to a hidden temporary file in the target directory, synced to disk, and renamed into place only once complete and verified. An interrupted or failed upload never replaces or truncates an existing file. The temporary files, named .weed-upload-\*, are invisible to WebDAV clients.
- LOCKs are honoured by every write, PUT and TPC pull included.
- MOVE overwrites by default, as RFC 4918 requires. COPY or MOVE of a directory onto itself or into one of its descendants is refused (403).
- PROPFIND with Depth: infinity (or without Depth) is refused (403): listing a whole tree is too expensive.
- Paths with encoded dot segments (%2e%2e) are refused.

A temporary file can stay behind if weed or the machine dies during an upload. Remove the old ones now and then:

    # find /data -name '.weed-upload-*' -mmin +1440 -delete

## Checksums

weed supports the digests of RFC 9530 (Repr-Digest) and, for older clients, RFC 3230 (Digest), with the algorithms adler (or adler32), crc32c, md5, sha, sha-256 and sha-512.

weed computes checksums only while it writes a file, on uploads (PUT) and third-party copy pulls: adler32 always, since WLCG clients ask for it afterwards, and the algorithms of the client's Repr-Digest. It stores them in extended attributes of the file, user.weed.digest.\<alg\>, each with the size and mtime (in nanoseconds) of the file it describes:

    # getfattr -d /data/alice/services
    # file: data/alice/services
    user.weed.digest.adler="692252:1793264797412873605:3c5e9d34"

Reads never compute a checksum, which would mean reading the whole file before answering. So a file has no checksum when:

- weed did not write it: other programs wrote it, or it is the copy of a local COPY (a MOVE keeps the checksums);
- its size or mtime has changed since weed wrote it;
- the filesystem has no user extended attributes: then no file has one.

A program that changes a file in place but keeps its size and restores its mtime leaves the old checksums, which weed cannot tell from current ones.

A PUT with a Repr-Digest header, e.g. `adler=:AAAAAQ==:, md5=:1B2M2Y8AsgTpgAmY7PhCfg==:`, is verified:

| Repr-Digest | Answer |
|----|----|
| absent | the upload is not verified |
| malformed | 400 |
| empty, or with none of the supported algorithms | 406 |
| a supported digest differs from the data received | 412, and the file is not stored |
| every supported digest matches | 201 or 204, with Repr-Digest |

GET and HEAD return Repr-Digest when asked with Want-Repr-Digest (e.g. `adler=9`), and Digest when asked with Want-Digest (e.g. `adler32`): of the stored checksums, the one the client prefers. With none of those it asks for stored, the answer has no checksum, and weed logs "no stored digest of the algorithms asked for". gfal-sum asks for it:

    $ gfal-sum davs://weed.example.org/webdav/alice/services ADLER32
    davs://weed.example.org/webdav/alice/services 3c5e9d34

The digests are base64, as RFC 9530 says. To compute one:

    $ openssl dgst -md5 -binary myfile | base64

Checksum mismatches are counted in `weed_checksum_mismatches_total`, by operation (put, tpc_pull, tpc_push).

## Performance

Uploads and third-party copies read the next MiB while the previous one is written and checksummed, and compute several digests in parallel, so that checksums cost little more than the slowest of network, disk and hashing. On an M1 Pro over loopback, with 2 GiB files: PUT or TPC pull with adler32 at about 2450 MB/s, with sha-256 as well at about 1900 MB/s; GET at about 3000 MB/s. md5 is the slow one, at about 650 MB/s. Measure on your hardware, from the source tree:

    $ WEED_BENCH_MIB=4096 make bench

## WebDAV

weed is meant for WLCG clients (gfal2, davix, FTS, XRootD), and deviates from RFC 4918 where they are not affected. In the litmus test suite, the basic, copymove and http tests pass; props and locks fail only on these:

- If headers: only lock tokens are evaluated; entity tags and Not are ignored. The HTTP If-Match and If-None-Match headers work.
- PROPPATCH stores nothing: each property is refused with 403 in the 207 answer.
- Shared locks get 501; exclusive locks work.
- A PROPFIND body that binds a prefix to the empty namespace is accepted, not refused with 400.
