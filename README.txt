WEED: WEbdav Exporter Daemon

WEED exports a local filesystem directory via the WebDAV protocol.
It implements RFCXXX and WLCG HTTP TPC Pull and Push models.
It supports basic and shared secret authentication mechanism.

No depencencies.

Works on Windows, Mac and Linux.


Behaviour when client sends the HTTP header "Repr-Digest", for example:
"adler=:123:,md5=:999:"

CONDITION                                            HTTP CODE
* header not present                              => 406 (Not acceptable)
* server does not implement client provided algos => 406 (Not acceptable)
* server digest is different from client digest   => 412 (Pre-condition failed)


Authentication mechanisms

1. Basic authentication
WEED supports basic authenticaton (RFC 7235/RFC 7617). Basically, a plain username/password pair
is sent encoded in base64. Example of a request:
    curl -X PROPFIND http://localhost:9000/ -u username:password

How to calculate a digest with the encoding expected?
$ cat myfile.html | openssl dgst -md5 -binary | base64

2. Bearer tokens
2.1 Macaroons
WEED implements the minimum Macaroons support to download and upload files.
WEED only understand the following caveats:

CAPABILITY              ACTIVITY
Read file    LIST,DOWNLOAD
Upload file  UP 

    - activity caveat. Read permissions map to activity:READ,DOWNLOAD
    A request is made using any previous authentication mechanism to request a bearer token with capabilities.
    Example request:
    curl -X POST \
        -d '{"caveats": ["activity:DOWNLOAD,LIST", "path:/dir_0/dir_1"}' \
        -H 'Content-Type: application/macaroon-request' \
        https://example.org/
    curl -X POST \
        -d '{"caveats": ["activity:DOWNLOAD,LIST"}' \
        -H 'Content-Type: application/macaroon-request' \
        https://example.org/dir_0/dir_1

2.2 SciTokens (derivation of OIDC tokens)
