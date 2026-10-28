#!/bin/bash
# Runs inside the weed-interop container (see interop.sh): two weed servers (A, B) and
# an XRootD server (X), exercised with gfal2, davix and curl using an RFC 3820 proxy,
# macaroons and tokens from a WLCG token issuer (I).
set -uo pipefail
W=/work
mkdir -p $W && cd $W || exit 1

pass=0 fail=0
check() {
	local name=$1
	shift
	local out
	if out=$("$@" 2>&1); then
		echo "PASS  $name"
		pass=$((pass + 1))
	else
		echo "FAIL  $name"
		echo "$out" | tail -15 | sed 's/^/      | /'
		fail=$((fail + 1))
	fi
}

# --- PKI: CA, host certificate for localhost, user certificate, RFC 3820 proxy
CERTS=/etc/grid-security/certificates
mkdir -p $CERTS
ssl() { openssl "$@" 2>/dev/null; }
ssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/DC=org/DC=weed/CN=Interop CA" \
	-addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
cp ca.pem $CERTS/$(openssl x509 -hash -noout -in ca.pem).0
issue() { # name subject signer-cert signer-key serial extensions
	ssl req -newkey rsa:2048 -nodes -keyout $1.key -out $1.csr -subj "$2"
	ssl x509 -req -in $1.csr -CA $3 -CAkey $4 -set_serial $5 -days 1 -out $1.pem -extfile <(printf "$6")
}
issue host "/DC=org/DC=weed/CN=localhost" ca.pem ca.key 2 \
	"subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n"
USER_DN="/DC=org/DC=weed/OU=Users/CN=Interop User"
issue user "$USER_DN" ca.pem ca.key 3 "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n"
issue proxy "$USER_DN/CN=1234567" user.pem user.key 1234567 \
	"keyUsage=critical,digitalSignature,keyEncipherment\nproxyCertInfo=critical,language:id-ppl-inheritAll\n"
cat proxy.pem proxy.key user.pem >/tmp/x509up_u0
chmod 600 /tmp/x509up_u0
export X509_USER_PROXY=/tmp/x509up_u0 X509_CERT_DIR=$CERTS

# A CRL made by openssl, installed the way fetch-crl does (<hash>.r0)
REVOKED_DN="/DC=org/DC=weed/OU=Users/CN=Revoked User"
issue revoked "$REVOKED_DN" ca.pem ca.key 4 "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
mkdir -p ca && touch ca/index.txt && echo 01 >ca/crlnumber
printf '[ca]\ndefault_ca = d\n[d]\ndatabase = ca/index.txt\ncrlnumber = ca/crlnumber\ndefault_md = sha256\ndefault_crl_days = 1\n' >ca.cnf
gencrl() { ssl ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.pem -out $CERTS/$(openssl x509 -hash -noout -in ca.pem).r0; }
gencrl

# --- WLCG token issuer; XRootD (scitokens-cpp) fetches its keys trusting the system CAs
cp ca.pem /etc/pki/ca-trust/source/anchors/interop-ca.pem && update-ca-trust
ssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out issuer.key
ISS=https://localhost:8446
issuer serve -url $ISS -signing-key issuer.key -cert host.pem -key host.key 2>$W/issuer.log &
token() { issuer mint -url $ISS -signing-key issuer.key "$@"; } # -aud AUD -scope SCOPES [-lifetime D]
printf '[{"issuer": "%s", "audiences": ["https://localhost:8443", "https://localhost:8444"]}]' $ISS >issuers.json

# --- servers
# A certificate from the CA that is not listed here, like unmapped.pem, is refused
printf '"%s" interop\n"%s" revoked\n' "$USER_DN" "$REVOKED_DN" >gridmap
issue unmapped "/DC=org/DC=weed/OU=Users/CN=Unmapped User" ca.pem ca.key 5 "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
mkdir -p /srv/a /srv/b
start_weed() { # name port [lines of further tables]; METRICS, ISSUERS, LOG_FORMAT
	(umask 077 && cat >weed-$1.toml) <<TOML
[server]
port = $2
dir = "/srv/$1"
log_file = "$W/weed-$1.log"
log_format = "${LOG_FORMAT:-text}"
metrics_address = "${METRICS:-}"
[tls]
enabled = true
cert = "host.pem"
key = "host.key"
[x509]
enabled = true
ca = "$CERTS"
crl_path = "$CERTS"
gridmap = "gridmap"
[macaroons]
enabled = true
secret_key = "$(openssl rand -hex 32)"
[tokens]
issuers = "${ISSUERS:-issuers.json}"
ca_path = "ca.pem"
[tpc]
enabled = true
ca_path = "$CERTS"
allow_local = true
marker_interval = "20ms"
TOML
	printf '%s\n' "${@:3}" >>weed-$1.toml
	weed -config weed-$1.toml &
}
METRICS=localhost:9100 start_weed a 8443
start_weed b 8444
# C accesses files as the Unix account of each identity, from a worker process per
# account: the grid-mapfile names the account for certificates, and for tokens a user
# rule does (the revoked DN has no account)
useradd -M -u 7001 interop && useradd -M -u 7002 robot
mkdir -p /srv/c/interop /srv/c/robot && chown interop: /srv/c/interop && chown robot: /srv/c/robot && chmod 700 /srv/c/robot
printf '[{"issuer": "%s", "audiences": ["https://localhost:8447"], "users": [{"group": "/interop/robots", "user": "robot"}]}]' $ISS >issuers-c.json
ISSUERS=issuers-c.json LOG_FORMAT=json METRICS=localhost:9101 start_weed c 8447 '[unix_users]' 'enabled = true' 'idle_timeout = "3s"'

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
check "gfal-sum md5" sh -c "gfal-sum $A/g.bin MD5 | grep -q \" \$(md5sum f.bin | cut -c1-32)\$\""
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
mkdir -p /srv/a/tok/up /srv/b/tok/up /srv/x/tok/up && cp f.bin /srv/a/tok/f.bin && cp f.bin /srv/x/tok/f.bin && chown -R xrootd /srv/x/tok
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

echo "== Unix accounts (unix_users)"
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
check "...owned by robot" owned robot /srv/c/robot/t.bin
check "...and cannot write to interop's directory" http_status 403 -H "Authorization: Bearer $ROBOT" -T f.bin $(https $C)/interop/t.bin
check "token no rule maps is refused" http_status 403 -H "Authorization: Bearer $(token -aud https://localhost:8447 -scope storage.read:/)" $(https $C)/interop/f.bin
check "certificate whose account does not exist is refused" http_status 403 --cert revoked.pem --key revoked.key $(https $C)/interop/f.bin
C_PID=$(pgrep -f 'weed -config weed-c.toml')
workers() { ps -o user=,args= --ppid $C_PID | awk '{print $1, $2, $3, $4}' | sort; }
workers_are() { [ "$(workers)" = "$(printf '%s\n' "$@")" ]; }
gfal-ls $C/interop >/dev/null; curl -s -o /dev/null --capath $CERTS -H "Authorization: Bearer $ROBOT" $(https $C)/robot/t.bin
check "ps shows a worker per account, running as it" workers_are "interop weed worker interop" "robot weed worker robot"
check "...while weed itself runs as root" [ "$(ps -o user= -p $C_PID)" = root ]
status_workers() { curl -s localhost:9101/status | jq -r '.workers[] | "\(.account) \(.pid)"' | sort; }
check "/status lists them, with their pids" eval '[ "$(status_workers)" = "$(ps -o user=,pid= --ppid $C_PID | awk "{print \$1, \$2}" | sort)" ]'
for i in $(seq 100); do [ -z "$(workers)" ] && break; sleep 0.1; done
check "idle workers stop (unix_users.idle_timeout)" workers_are
check "...and start again when needed" gfal-ls $C/interop

echo "== grid-mapfile, revocation and reloading"
check "valid certificate with an openssl CRL" $CURL -o /dev/null https://localhost:8443/webdav/g.bin
UCURL="curl -sS -o /dev/null -w %{http_code} --capath $CERTS --cert unmapped.pem --key unmapped.key"
check "certificate not in the grid-mapfile refused" sh -c "[ \$($UCURL https://localhost:8443/webdav/g.bin) = 403 ]"
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
curl -s localhost:9100/metrics >metrics.txt
check "/healthz" sh -c "[ \"\$(curl -s localhost:9100/healthz)\" = ok ]"
check "TPC transfers counted" grep -qE '^weed_tpc_transfers_total\{mode="push",result="success"\} [1-9]' metrics.txt
check "checksum mismatches counted" grep -qE '^weed_checksum_mismatches_total\{operation="tpc_push"\} [1-9]' metrics.txt
check "CRL and certificate expiry exported" sh -c "grep -q '^weed_crl_expiry_timestamp_seconds ' metrics.txt && grep -q '^weed_tls_certificate_expiry_timestamp_seconds ' metrics.txt"

echo "== what runs: build, start, configuration, pending restart"
SHA=$(sha256sum weed-a.toml | cut -d' ' -f1)
curl -s localhost:9100/status >status.json
check "weed check: A's configuration is valid" sh -c "weed check -config weed-a.toml | grep -q 'sha256 $SHA'"
check "weed check: C's (unix_users) too" weed check -config weed-c.toml
check "/status: the configuration's SHA-256 is the file's" sh -c "[ \"\$(jq -r .config.sha256 status.json)\" = $SHA ]"
check "/status: the build is weed version's" sh -c "weed version | grep -qx \"build    \$(jq -r .version.build status.json)\""
SECRET=$(sed -n 's/^secret_key = "\(.*\)"$/\1/p' weed-a.toml)
check "/status: started, settings, no secrets" eval '[ -n "$SECRET" ] && ! grep -qF "$SECRET" status.json &&
	jq -e ".pid > 0 and .started != null and .config.settings.server.port == 8443 and .config.settings.macaroons.secret_key == \"<redacted>\"" status.json >/dev/null'
check "no restart pending" grep -qx 'weed_restart_pending{reason="config"} 0' metrics.txt
check "build and configuration exported" sh -c "grep -q '^weed_build_info{.*build=\"go:' metrics.txt && grep -q \"^weed_config_info{.*sha256=\\\"$SHA\\\"} 1\" metrics.txt && grep -q '^process_start_time_seconds ' metrics.txt"
cp weed-a.toml weed-a.toml.orig
sed -i 's/^marker_interval = .*/marker_interval = "5s"/' weed-a.toml
check "edited configuration: restart pending, naming the option" sh -c "curl -s localhost:9100/metrics | grep -qx 'weed_restart_pending{reason=\"config\"} 1' &&
	grep -q 'level=WARN msg=\"restart pending: the configuration file has changed: tpc.marker_interval\"' $W/weed-a.log"
echo '[server' >>weed-a.toml
check "broken configuration: weed check fails" sh -c "! weed check -config weed-a.toml 2>check.err && grep -q 'weed would not start' check.err"
check "broken configuration: logged as an error now" sh -c "curl -s localhost:9100/status | jq -e '.restart_pending.config | contains(\"would not start\")' >/dev/null &&
	grep -q 'level=ERROR msg=\"restart pending: the configuration file has changed, and weed would not start' $W/weed-a.log"
cp weed-a.toml.orig weed-a.toml
check "restored configuration: no restart pending" sh -c "curl -s localhost:9100/metrics | grep -qx 'weed_restart_pending{reason=\"config\"} 0'"

echo
echo "$pass passed, $fail failed"
if [ $fail -gt 0 ]; then
	for log in $W/weed-a.log $W/weed-b.log $W/weed-c.log $(find $XRD -name xrootd.log); do
		echo "--- tail $log"
		tail -30 $log
	done
	exit 1
fi
