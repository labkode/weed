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
