#!/bin/bash
# Runs inside the weed-interop container (see interop.sh): two weed servers (A, B) and
# an XRootD server (X), exercised with gfal2, davix and curl using an RFC 3820 proxy,
# macaroons and tokens from a WLCG token issuer (I).
set -uo pipefail
W=/work
mkdir -p $W && cd $W || exit 1

. "$(dirname "$0")/lib.sh"

# --- PKI: CA, host certificate for localhost, user certificate, RFC 3820 proxy
make_pki
use_pki

# A certificate to revoke later, which the CRL (gencrl) lists then
REVOKED_DN="/DC=org/DC=weed/OU=Users/CN=Revoked User"
issue revoked "$REVOKED_DN" ca.pem ca.key 4 "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"

# --- WLCG token issuer; XRootD (scitokens-cpp) fetches its keys trusting the system CAs
cp ca.pem /etc/pki/ca-trust/source/anchors/interop-ca.pem && update-ca-trust
ssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out issuer.key
ISS=https://localhost:8446
issuer serve -url $ISS -signing-key issuer.key -cert host.pem -key host.key 2>$W/issuer.log &
token() { issuer mint -url $ISS -signing-key issuer.key "$@"; } # -aud AUD -scope SCOPES [-lifetime D]
printf '[{"issuer": "%s", "audiences": ["https://localhost:8443", "https://localhost:8444"], "users": [{"sub": "interop-token-user", "user": "interop"}]}]' $ISS >issuers.json

# --- servers
# weed accesses files as the Unix account of each identity, from a worker process per
# account: the grid-mapfile names the account for certificates, and for tokens the
# subject or a user rule does. A certificate from the CA that is not listed here, like
# unmapped.pem, is refused, and so is one whose account does not exist (ghost.pem).
useradd -M -u 7001 interop && useradd -M -u 7002 robot && useradd -M -u 7003 revoked
GHOST_DN="/DC=org/DC=weed/OU=Users/CN=Ghost User"
printf '"%s" interop\n"%s" revoked\n"%s" ghost\n' "$USER_DN" "$REVOKED_DN" "$GHOST_DN" >gridmap
issue unmapped "/DC=org/DC=weed/OU=Users/CN=Unmapped User" ca.pem ca.key 5 "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
issue ghost "$GHOST_DN" ca.pem ca.key 6 "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
mkdir -p /srv/a /srv/b && chown interop: /srv/a /srv/b
METRICS=localhost:9180 start_weed a 8443
start_weed b 8444
# C has a directory per account, and maps tokens to accounts by their groups
mkdir -p /srv/c/interop /srv/c/robot && chown interop: /srv/c/interop && chown robot: /srv/c/robot && chmod 700 /srv/c/robot
printf '[{"issuer": "%s", "audiences": ["https://localhost:8447"], "users": [{"group": "/interop/robots", "user": "robot"}]}]' $ISS >issuers-c.json
ISSUERS=issuers-c.json LOG_FORMAT=json METRICS=localhost:9101 start_weed c 8447 '[unix_users]' 'idle_timeout = "3s"'

# XRootD as a production-like WLCG endpoint: X.509 over HTTPS, macaroons, tokens, HTTP-TPC.
# It runs as the xrootd user, which needs a writable working directory.
XRD=/var/run/xrootd-interop
mkdir -p /srv/x /etc/xrootd/tls $XRD
cp host.pem host.key /etc/xrootd/tls/
openssl rand -base64 -out /etc/xrootd/macaroon-secret 64
# Only the mapped X.509 user may do anything without a token, or token checks would
# prove nothing
cp gridmap /etc/xrootd/gridmap
echo "u interop /srv/x a" >/etc/xrootd/Authfile
chown -R xrootd /srv/x /etc/xrootd/tls /etc/xrootd/macaroon-secret /etc/xrootd/Authfile /etc/xrootd/gridmap $XRD
chmod 400 /etc/xrootd/tls/host.key /etc/xrootd/macaroon-secret
cat >/etc/xrootd/scitokens.cfg <<CFG
[Global]
audience = https://localhost:8445

[Issuer interop]
issuer = $ISS
base_path = /srv/x
default_user = xrootd
CFG
cat >xrootd.cfg <<CFG
all.sitename interop
all.export /srv/x
xrd.port 1094
xrd.protocol XrdHttp:8445 libXrdHttp.so
xrd.tls /etc/xrootd/tls/host.pem /etc/xrootd/tls/host.key
xrd.tlsca certdir $CERTS
ofs.authorize 1
acc.authdb /etc/xrootd/Authfile
http.gridmap /etc/xrootd/gridmap
ofs.authlib ++ libXrdAccSciTokens.so config=/etc/xrootd/scitokens.cfg
http.header2cgi Authorization authz
ofs.authlib ++ libXrdMacaroons.so
http.exthandler xrdmacaroons libXrdMacaroons.so
macaroons.secretkey /etc/xrootd/macaroon-secret
xrootd.chksum adler32
http.exthandler xrdtpc libXrdHttpTPC.so
# weed runs on localhost in this test
tpc.allow local
tpc.allow private
CFG
(cd $XRD && xrootd -c $W/xrootd.cfg -l $XRD/xrootd.log -R xrootd -n interop -b)

A=davs://localhost:8443/webdav B=davs://localhost:8444/webdav X=davs://localhost:8445/srv/x C=davs://localhost:8447/webdav
https() { echo "${1/davs:/https:}"; }
for url in $A $B $X $C; do
	for i in $(seq 50); do
		curl -s -o /dev/null --capath $CERTS "$(https $url)/" && break
		sleep 0.2
	done
done

CURL="curl -sS --fail-with-body --capath $CERTS --cert $X509_USER_PROXY --key $X509_USER_PROXY"
DAVIX="-E $X509_USER_PROXY --capath $CERTS"
TPC=(-D "HTTP PLUGIN:ENABLE_FALLBACK_TPC_COPY=false")
adler() { python3 -c 'import sys, zlib; print("%08x" % zlib.adler32(open(sys.argv[1], "rb").read()))' "$1"; }
mint() { # url activities -> macaroon
	$CURL -X POST -H 'Content-Type: application/macaroon-request' \
		-d "{\"caveats\": [\"activity:$2\"], \"validity\": \"PT10M\"}" "$(https $1)" | jq -r .macaroon
}
# tpc_curl active-url header... : prints the marker stream, fails unless it ends with success
tpc_curl() {
	local url=$1
	shift
	local out
	out=$($CURL -X COPY "$@" "$(https $url)") || { echo "$out"; return 1; }
	echo "$out"
	[ "$(echo "$out" | tail -1)" = "success: Created" ]
}

head -c 5000000 /dev/urandom >f.bin
SUM=$(adler f.bin)

check "weed A, B and C confine themselves with Landlock" sh -c "grep -q 'weed confines itself with Landlock' $W/weed-a.log &&
	grep -q 'weed confines itself with Landlock' $W/weed-b.log && grep -q 'weed confines itself with Landlock' $W/weed-c.log"

echo "== davix against weed"
check "davix-put" davix-put $DAVIX f.bin $A/davix.bin
check "davix-get matches" sh -c "davix-get $DAVIX $A/davix.bin got.bin && cmp f.bin got.bin"
check "davix-ls" sh -c "davix-ls $DAVIX $A/ | grep -qx davix.bin"
check "davix-mkdir" davix-mkdir $DAVIX $A/dir
# davix-mv 0.8.10 exits 255 after a successful MOVE (against XRootD too), so check the outcome
check "davix-mv" sh -c "davix-mv $DAVIX $A/davix.bin $A/dir/davix.bin; test -f /srv/a/dir/davix.bin && ! test -e /srv/a/davix.bin"
MAC=$(mint $A/dir/davix.bin DOWNLOAD)
check "davix-get with a macaroon only" sh -c "davix-get --capath $CERTS -H 'Authorization: Bearer $MAC' $A/dir/davix.bin mac.bin && cmp f.bin mac.bin"
check "davix-rm" sh -c "davix-rm $DAVIX $A/dir/davix.bin && ! test -e /srv/a/dir/davix.bin"

echo "== gfal2 against weed"
check "gfal-copy upload with adler32 check" gfal-copy -f -K ADLER32 file://$W/f.bin $A/g.bin
check "gfal-sum adler32" sh -c "gfal-sum $A/g.bin ADLER32 | grep -q ' $SUM\$'"
# weed computes checksums while it writes a file, never on reads: md5 only if the
# upload sent it
MD5=$(md5sum f.bin | cut -c1-32)
MD5REPR="md5=:$(python3 -c "import base64; print(base64.b64encode(bytes.fromhex('$MD5')).decode())"):"
check "gfal-sum md5 of an upload that sent it" sh -c "$CURL -T f.bin -H 'Repr-Digest: $MD5REPR' $(https $A)/m.bin >/dev/null && gfal-sum $A/m.bin MD5 | grep -q ' $MD5\$'"
check "no md5 of an upload that did not send it" sh -c "! gfal-sum $A/g.bin MD5"
check "gfal-stat size" sh -c "gfal-stat $A/g.bin | grep -q 'Size: 5000000'"
check "gfal-ls" sh -c "gfal-ls $A/ | grep -qx g.bin"
check "gfal-mkdir -p" sh -c "gfal-mkdir -p $A/d1/d2 && test -d /srv/a/d1/d2"
check "gfal-rename" sh -c "gfal-copy -f file://$W/f.bin $A/d1/r.bin && gfal-rename $A/d1/r.bin $A/d1/d2/r.bin && test -f /srv/a/d1/d2/r.bin"
check "gfal-rm -r" sh -c "gfal-rm -r $A/d1 && ! test -e /srv/a/d1"
check "gfal-copy download" sh -c "gfal-copy -f $A/g.bin file://$W/down.bin && cmp f.bin down.bin"

echo "== third-party copy between two weed servers, driven by gfal2"
check "gfal-copy pull A->B" gfal-copy -f --copy-mode pull "${TPC[@]}" -K ADLER32 $A/g.bin $B/pull.bin
check "pulled file matches" cmp f.bin /srv/b/pull.bin
# A transfer long enough for performance markers, which gfal2 must parse
head -c 1500000000 /dev/zero >/srv/a/big.bin
# gfal-copy -v prints a "monitor:" line (src dst avg inst bytes elapsed) per marker it parsed
check "gfal-copy pull of 1.5 GB with performance markers" sh -c "gfal-copy -f -v --copy-mode pull ${TPC[*]@Q} $A/big.bin $B/big.bin >big.log 2>&1 &&
	awk '/^monitor:/ && \$6 > 0 && \$6 < 1500000000 { found = 1 } END { exit !found }' big.log && cmp /srv/a/big.bin /srv/b/big.bin"
rm -f /srv/a/big.bin /srv/b/big.bin
check "gfal-copy push A->B" gfal-copy -f --copy-mode push "${TPC[@]}" -K ADLER32 $A/g.bin $B/push.bin
check "pushed file matches" cmp f.bin /srv/b/push.bin

echo "== third-party copy between weed and XRootD"
check "XRootD pulls from weed (gfal2)" gfal-copy -f --copy-mode pull "${TPC[@]}" $A/g.bin $X/from-weed.bin
check "XRootD's copy matches" cmp f.bin /srv/x/from-weed.bin
check "XRootD pushes to weed (gfal2)" gfal-copy -f --copy-mode push "${TPC[@]}" $X/from-weed.bin $B/from-xrootd-push.bin
check "weed's copy matches" cmp f.bin /srv/b/from-xrootd-push.bin
check "weed pulls from XRootD (gfal2)" gfal-copy -f --copy-mode pull "${TPC[@]}" -K ADLER32 $X/from-weed.bin $B/from-xrootd-pull.bin
check "weed's copy matches" cmp f.bin /srv/b/from-xrootd-pull.bin
check "weed pushes to XRootD (gfal2)" gfal-copy -f --copy-mode push "${TPC[@]}" -K ADLER32 $A/g.bin $X/from-weed-push.bin
check "XRootD's copy matches" cmp f.bin /srv/x/from-weed-push.bin

echo "== data-integrity extension (curl)"
REPR="adler=:$(python3 -c "import base64; print(base64.b64encode(bytes.fromhex('$SUM')).decode())"):"
check "weed pulls from XRootD with Repr-Digest" tpc_curl $B/x-ok.bin -H "Source: $(https $X)/from-weed.bin" -H "Repr-Digest: $REPR"
check "weed rejects a pull with the wrong digest" sh -c "! $CURL -X COPY -H 'Source: $(https $X)/from-weed.bin' -H 'Repr-Digest: adler=:AAAAAA==:' $(https $B)/x-bad.bin | tail -1 | grep -q '^success' && ! test -e /srv/b/x-bad.bin"
MAC=$(mint $A/g.bin DOWNLOAD)
check "XRootD pulls with a weed macaroon" tpc_curl $X/mac.bin -H "Source: $(https $A)/g.bin" -H "TransferHeaderAuthorization: Bearer $MAC"
MACB=$(mint $B/pushed-mac.bin UPLOAD)
check "weed pushes with Repr-Digest; destination verifies" tpc_curl $A/g.bin -H "Destination: $(https $B)/pushed-mac.bin" \
	-H "TransferHeaderAuthorization: Bearer $MACB" -H "Repr-Digest: $REPR"
MACB=$(mint $B/pushed-bad.bin UPLOAD)
check "push with wrong digest fails with 412 from destination" sh -c "$CURL -X COPY -H 'Destination: $(https $B)/pushed-bad.bin' \
	-H 'TransferHeaderAuthorization: Bearer $MACB' -H 'Repr-Digest: adler=:AAAAAA==:' $(https $A)/g.bin | tail -1 | grep -q 'checksum mismatch reported by destination'"

echo "== WLCG tokens (no client certificate)"
mv /tmp/x509up_u0 proxy.off
mkdir -p /srv/a/tok/up /srv/b/tok/up /srv/x/tok/up && cp f.bin /srv/a/tok/f.bin && cp f.bin /srv/x/tok/f.bin && chown -R xrootd /srv/x/tok &&
	chown -R interop: /srv/a/tok /srv/b/tok
AUDS=https://localhost:8443,https://localhost:8444,https://localhost:8445
READ=$(token -aud $AUDS -scope storage.read:/tok)
CREATE=$(token -aud $AUDS -scope "storage.read:/tok storage.create:/tok/up")
MODIFY=$(token -aud $AUDS -scope storage.modify:/tok/up)
status() { # want token curl-args...: the HTTP status is want
	local got
	got=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $2" "${@:3}")
	[ "$got" = "$1" ] || { echo "HTTP $got, want $1"; return 1; }
}
# A token for another audience is invalid for weed (401), and forbidden for XRootD
for srv in "weed https://localhost:8443/webdav 401" "XRootD https://localhost:8445/srv/x 403"; do
	set -- $srv
	check "$1: storage.read allows reading" status 200 $READ $2/tok/f.bin -o /dev/null
	check "$1: storage.read does not allow writing" status 403 $READ -T f.bin $2/tok/up/r.bin
	check "$1: storage.create allows creating" status 201 $CREATE -T f.bin $2/tok/up/c.bin
	check "$1: storage.create does not allow overwriting" status 403 $CREATE -T f.bin $2/tok/up/c.bin
	check "$1: token for another service refused" status $3 "$(token -aud https://other.example -scope storage.read:/tok)" $2/tok/f.bin
done
check "weed: expired token refused" status 401 "$(token -aud $AUDS -scope storage.read:/tok -lifetime -1h)" https://localhost:8443/webdav/tok/f.bin
check "weed: storage.modify allows overwriting" status 204 $MODIFY -T f.bin https://localhost:8443/webdav/tok/up/c.bin
check "davix: download with a token" sh -c "env -u X509_USER_PROXY davix-get -H 'Authorization: Bearer $READ' https://localhost:8443/webdav/tok/f.bin dl-tok.bin && cmp f.bin dl-tok.bin"
check "gfal2: list with a token" env -u X509_USER_PROXY BEARER_TOKEN=$READ gfal-ls $A/tok
check "gfal2: upload with storage.create, checksum verified" env -u X509_USER_PROXY BEARER_TOKEN=$CREATE gfal-copy -K ADLER32 file://$W/f.bin $A/tok/up/g.bin
check "gfal2: storage.create does not allow replacing" sh -c "! env -u X509_USER_PROXY BEARER_TOKEN=$CREATE gfal-copy -f file://$W/f.bin $A/tok/up/g.bin"
check "gfal2: storage.modify allows replacing" env -u X509_USER_PROXY BEARER_TOKEN=$MODIFY gfal-copy -f file://$W/f.bin $A/tok/up/g.bin
# One token, accepted by all three servers, for third-party copies driven by gfal2
for t in "A $A B $B" "A $A X $X" "X $X A $A"; do
	set -- $t
	for mode in pull push; do
		dst=$4/tok/up/$1-$3-$mode.bin
		check "gfal2 TPC $mode with a token: $1 -> $3" env -u X509_USER_PROXY BEARER_TOKEN=$CREATE \
			gfal-copy --copy-mode $mode -K ADLER32 "${TPC[@]}" $2/tok/f.bin $dst
		check "copy matches" cmp f.bin /srv/$(echo $3 | tr ABX abx)/tok/up/$1-$3-$mode.bin
	done
done
# weed as the passive party: the token arrives from XRootD in TransferHeaderAuthorization
xrootd_push() { # name: XRootD pushes tok/f.bin to weed's tok/up/name; prints the final marker line
	curl -sS -X COPY -H "Authorization: Bearer $CREATE" -H "Destination: https://localhost:8443/webdav/tok/up/$1" \
		-H "TransferHeaderAuthorization: Bearer $CREATE" https://localhost:8445/srv/x/tok/f.bin | tail -1
}
pushed() { local last; last=$(xrootd_push $1); [ "$last" = "success: Created" ] || { echo "$last"; return 1; }; }
refused() { local last; last=$(xrootd_push $1); echo "$last"; [[ $last == failure* ]]; }
check "XRootD pushes to weed with a token" pushed x-push.bin
check "copy matches" cmp f.bin /srv/a/tok/up/x-push.bin
check "...and cannot replace it with storage.create" refused x-push.bin
check "weed refuses a pull onto an existing file with storage.create" status 403 $CREATE -X COPY \
	-H "Source: https://localhost:8445/srv/x/tok/f.bin" -H "TransferHeaderAuthorization: Bearer $READ" https://localhost:8443/webdav/tok/up/g.bin
mv proxy.off /tmp/x509up_u0

echo "== Unix accounts"
owned() { [ "$(stat -c %U "$2")" = "$1" ]; } # user path
http_status() { # want curl-args...
	[ "$(curl -s -o /dev/null -w '%{http_code}' --capath $CERTS "${@:2}")" = "$1" ]
}
check "gfal2 upload as the grid-mapfile's account" gfal-copy -f file://$W/f.bin $C/interop/f.bin
check "...owned by it" owned interop /srv/c/interop/f.bin
check "gfal2 mkdir" gfal-mkdir $C/interop/dir
check "...owned by it" owned interop /srv/c/interop/dir
check "another account's private directory cannot be listed" sh -c "! gfal-ls $C/robot"
check "...nor written to" sh -c "! gfal-copy -f file://$W/f.bin $C/robot/f.bin"
check "gfal2 TPC pull from weed A" gfal-copy -f "${TPC[@]}" $A/g.bin $C/interop/pulled.bin
check "...owned by the account" owned interop /srv/c/interop/pulled.bin
check "...logged by its worker, in weed's log" grep -q '"msg":"third-party copy completed","worker":{"user":"interop","pid":[0-9]*}.*"request_id":' $W/weed-c.log
ROBOT=$(token -aud https://localhost:8447 -scope "storage.read:/ storage.modify:/" -groups /interop/robots)
check "token mapped by its group writes as robot" http_status 201 -H "Authorization: Bearer $ROBOT" -T f.bin $(https $C)/robot/t.bin
check "...logged as robot" grep -q '"msg":"request","method":"PUT","path":"/webdav/robot/t.bin",.*"status":201,.*"user":"robot"' $W/weed-c.log
check "...owned by robot" owned robot /srv/c/robot/t.bin
check "...and cannot write to interop's directory" http_status 403 -H "Authorization: Bearer $ROBOT" -T f.bin $(https $C)/interop/t.bin
check "token no rule maps is refused" http_status 403 -H "Authorization: Bearer $(token -aud https://localhost:8447 -scope storage.read:/)" $(https $C)/interop/f.bin
check "certificate whose account does not exist is refused" http_status 403 --cert ghost.pem --key ghost.key $(https $C)/interop/f.bin
check "...logged as its account" grep -q '"msg":"request","method":"GET","path":"/webdav/interop/f.bin",.*"status":403,.*"user":"ghost"' $W/weed-c.log
C_PID=$(pgrep -f 'weed -config weed-c.toml')
C_STARTER=$(pgrep -P $C_PID | head -1) # weed's only child; its workers are the starter's
workers() { ps -o user=,args= --ppid $C_STARTER | awk '{print $1, $2, $3, $4}' | sort; }
workers_are() { [ "$(workers)" = "$(printf '%s\n' "$@")" ]; }
gfal-ls $C/interop >/dev/null; curl -s -o /dev/null --capath $CERTS -H "Authorization: Bearer $ROBOT" $(https $C)/robot/t.bin
check "ps shows a worker per account, running as it" workers_are "interop weed worker interop" "robot weed worker robot"
check "...while weed itself runs as root" [ "$(ps -o user= -p $C_PID)" = root ]
status_workers() { curl -s localhost:9101/status | jq -r '.workers[] | "\(.account) \(.pid)"' | sort; }
check "/status lists them, with their pids" eval '[ "$(status_workers)" = "$(ps -o user=,pid= --ppid $C_STARTER | awk "{print \$1, \$2}" | sort)" ]'
for i in $(seq 100); do [ -z "$(workers)" ] && break; sleep 0.1; done
check "idle workers stop (unix_users.idle_timeout)" workers_are
check "...and start again when needed" gfal-ls $C/interop

echo "== Banning users (weed utils, through the control plane)"
check "weed utils ban" sh -c "weed utils ban -config weed-c.toml -reason 'interop test' interop | grep -q '^banned interop'"
check "...stops the user's worker processes at once" sh -c "! workers | grep -q 'weed worker interop'"
check "...and weed refuses its requests" sh -c "! gfal-ls $C/interop"
check "...logged as the user" grep -q '"msg":"request","method":"PROPFIND","path":"/webdav/interop/\?",.*"status":403,.*"user":"interop"' $W/weed-c.log
check "...with the reason" grep -q '"msg":"authentication failed",.*"error":"forbidden: interop is banned (since ' $W/weed-c.log
check "...and who banned it" grep -q '"msg":"user banned",.*"user":"interop","reason":"interop test","by":"uid 0, pid [0-9]*"' $W/weed-c.log
check "weed utils bans lists it" sh -c "weed utils bans -config weed-c.toml | grep -q '^interop .* uid 0, pid [0-9]* *interop test\$'"
check "...as /status counts it" sh -c "curl -s localhost:9101/status | jq -e '.banned_users == 1' >/dev/null"
check "...kept in admin.bans for the next start" jq -e '.[0].user == "interop" and .[0].reason == "interop test"' $W/bans-c.json
check "the control plane is only root's" sh -c "! setpriv --reuid=65534 --regid=65534 --clear-groups weed utils bans -socket /run/weed/c.sock"
check "weed utils unban" sh -c "weed utils unban -config weed-c.toml interop | grep -qx 'lifted the ban of interop'"
check "...serves the user again" gfal-ls $C/interop

echo "== Transfers in progress"
(head -c 5 f.bin; sleep 3) | curl -s -o /dev/null --capath $CERTS -H "Authorization: Bearer $ROBOT" -T - $(https $C)/robot/slow.bin &
SLOW=$!
in_progress() { curl -s localhost:9101/status | jq -e "$1" >/dev/null; }
check "/status counts them, by kind and user" sh -c "for i in \$(seq 50); do curl -s localhost:9101/status |
	jq -e '.in_progress.by_user == {\"robot\": {\"upload\": 1}} and .in_progress.total.upload == 1' >/dev/null && exit; sleep 0.1; done; exit 1"
check "...as weed_requests_in_progress does" sh -c "curl -s localhost:9101/metrics | grep -qx 'weed_requests_in_progress{kind=\"upload\"} 1'"
wait $SLOW
check "...until they end" sh -c "curl -s localhost:9101/status | jq -e '.in_progress.by_user == {} and ([.in_progress.total[]] | add) == 0' >/dev/null"

echo "== grid-mapfile, revocation and reloading"
check "valid certificate with an openssl CRL" $CURL -o /dev/null https://localhost:8443/webdav/g.bin
check "...logged as the grid-mapfile's user" grep -q 'msg=request method=GET path=/webdav/g.bin proto=HTTP/[0-9.]* status=200 .* user=interop ' $W/weed-a.log
UCURL="curl -sS -o /dev/null -w %{http_code} --capath $CERTS --cert unmapped.pem --key unmapped.key"
check "certificate not in the grid-mapfile refused" sh -c "[ \$($UCURL https://localhost:8443/webdav/g.bin) = 403 ]"
check "...logged as nobody" grep -q 'msg=request method=GET path=/webdav/g.bin proto=HTTP/[0-9.]* status=403 .* user=nobody ' $W/weed-a.log
RCURL="curl -sS -o /dev/null -w %{http_code} --capath $CERTS --cert revoked.pem --key revoked.key"
check "certificate accepted before revocation" sh -c "[ \$($RCURL https://localhost:8443/webdav/g.bin) = 200 ]"
ssl ca -config ca.cnf -revoke revoked.pem -keyfile ca.key -cert ca.pem
gencrl
pkill -HUP -f 'weed -config weed-a.toml'
# wait for the reload to be logged (once at startup, once after SIGHUP)
for i in $(seq 50); do [ "$(grep -c 'msg="loaded CRLs" .* crls=1 ' $W/weed-a.log)" -ge 2 ] && break; sleep 0.1; done
check "revoked certificate rejected after SIGHUP" sh -c "[ \$($RCURL https://localhost:8443/webdav/g.bin) = 401 ]"
check "other users unaffected" $CURL -o /dev/null https://localhost:8443/webdav/g.bin

echo "== metrics"
curl -s localhost:9180/metrics >metrics.txt
check "/healthz" sh -c "[ \"\$(curl -s localhost:9180/healthz)\" = ok ]"
check "TPC transfers counted" grep -qE '^weed_tpc_transfers_total\{mode="push",result="success"\} [1-9]' metrics.txt
check "checksum mismatches counted" grep -qE '^weed_checksum_mismatches_total\{operation="tpc_push"\} [1-9]' metrics.txt
check "CRL and certificate expiry exported" sh -c "grep -q '^weed_crl_expiry_timestamp_seconds ' metrics.txt && grep -q '^weed_tls_certificate_expiry_timestamp_seconds ' metrics.txt"

echo "== what runs: build, start, configuration, pending restart"
SHA=$(sha256sum weed-a.toml | cut -d' ' -f1)
curl -s localhost:9180/status >status.json
check "weed check: A's configuration is valid" sh -c "weed check -config weed-a.toml | grep -q 'sha256 $SHA'"
check "weed check: C's too" weed check -config weed-c.toml
check "/status: the configuration's SHA-256 is the file's" sh -c "[ \"\$(jq -r .config.sha256 status.json)\" = $SHA ]"
check "/status: the build is weed version's" sh -c "weed version | grep -qx \"build    \$(jq -r .version.build status.json)\""
SECRET=$(sed -n 's/^secret_key = "\(.*\)"$/\1/p' weed-a.toml)
check "/status: started, settings, no secrets" eval '[ -n "$SECRET" ] && ! grep -qF "$SECRET" status.json &&
	jq -e ".pid > 0 and .started != null and .config.settings.server.port == 8443 and .config.settings.macaroons.secret_key == \"<redacted>\"" status.json >/dev/null'
check "no restart pending" grep -qx 'weed_restart_pending{reason="config"} 0' metrics.txt
check "build and configuration exported" sh -c "grep -q '^weed_build_info{.*build=\"go:' metrics.txt && grep -q \"^weed_config_info{.*sha256=\\\"$SHA\\\"} 1\" metrics.txt && grep -q '^process_start_time_seconds ' metrics.txt"
cp weed-a.toml weed-a.toml.orig
sed -i 's/^marker_interval = .*/marker_interval = "5s"/' weed-a.toml
check "edited configuration: restart pending, naming the option" sh -c "curl -s localhost:9180/metrics | grep -qx 'weed_restart_pending{reason=\"config\"} 1' &&
	grep -q 'level=WARN msg=\"restart pending: the configuration file has changed: tpc.marker_interval\"' $W/weed-a.log"
echo '[server' >>weed-a.toml
check "broken configuration: weed check fails" sh -c "! weed check -config weed-a.toml 2>check.err && grep -q 'weed would not start' check.err"
check "broken configuration: logged as an error now" sh -c "curl -s localhost:9180/status | jq -e '.restart_pending.config | contains(\"would not start\")' >/dev/null &&
	grep -q 'level=ERROR msg=\"restart pending: the configuration file has changed, and weed would not start' $W/weed-a.log"
cp weed-a.toml.orig weed-a.toml
check "restored configuration: no restart pending" sh -c "curl -s localhost:9180/metrics | grep -qx 'weed_restart_pending{reason=\"config\"} 0'"
# Without a configuration file there is no metrics_address: the main port serves them
mkdir -p /srv/q && (cd /srv/q && exec weed 2>$W/weed-q.log) &
Q_PID=$!
for i in $(seq 50); do curl -sf localhost:9000/healthz >/dev/null && break; sleep 0.1; done
check "without a configuration file: weed confines itself with Landlock" grep -q 'weed confines itself with Landlock' $W/weed-q.log
check "...and /status on the main port" sh -c "curl -sf localhost:9000/status | jq -e '.config.file == \"\" and .config.settings.server.anonymous' >/dev/null"
check "...and /metrics" sh -c "curl -sf localhost:9000/metrics | grep -q '^weed_build_info{'"
check "...and weed utils reaches its control plane at the default socket" sh -c "weed utils bans | grep -qx 'no user is banned'"
check "...anonymous uploads belong to nobody" sh -c "! curl -sf -T f.bin localhost:9000/webdav/f.bin && chmod 1777 /srv/q &&
	curl -sf -T f.bin localhost:9000/webdav/f.bin && [ \$(stat -c %U /srv/q/f.bin) = nobody ]"
kill $Q_PID

echo
echo "$pass passed, $fail failed"
if [ $fail -gt 0 ]; then
	for log in $W/weed-a.log $W/weed-b.log $W/weed-c.log $(find $XRD -name xrootd.log); do
		echo "--- tail $log"
		tail -30 $log
	done
	exit 1
fi
