#!/bin/bash
# Runs inside the weed-interop container (see interop.sh): two weed servers (A, B) and
# an XRootD server (X), exercised with gfal2, davix and curl using an RFC 3820 proxy.
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

# --- servers
echo "\"$USER_DN\" interop" >gridmap
mkdir -p /srv/a /srv/b
start_weed() { # name port
	weed -port $2 -dir /srv/$1 -tls -tls-cert host.pem -tls-key host.key \
		-x509-auth -ca-cert ca.pem -gridmap-file gridmap \
		-macaroon-auth -macaroon-secret-key "$(openssl rand -hex 32)" \
		-tpc -tpc-ca-path $CERTS -tpc-allow-local -tpc-marker-interval 20ms \
		-log-file $W/weed-$1.log &
}
start_weed a 8443
start_weed b 8444

# XRootD as a production-like WLCG endpoint: X.509 over HTTPS, macaroons, HTTP-TPC.
# It runs as the xrootd user, which needs a writable working directory.
XRD=/var/run/xrootd-interop
mkdir -p /srv/x /etc/xrootd/tls $XRD
cp host.pem host.key /etc/xrootd/tls/
openssl rand -base64 -out /etc/xrootd/macaroon-secret 64
echo "u * /srv/x a" >/etc/xrootd/Authfile
chown -R xrootd /srv/x /etc/xrootd/tls /etc/xrootd/macaroon-secret /etc/xrootd/Authfile $XRD
chmod 400 /etc/xrootd/tls/host.key /etc/xrootd/macaroon-secret
cat >xrootd.cfg <<CFG
all.sitename interop
all.export /srv/x
xrd.port 1094
xrd.protocol XrdHttp:8445 libXrdHttp.so
xrd.tls /etc/xrootd/tls/host.pem /etc/xrootd/tls/host.key
xrd.tlsca certdir $CERTS
ofs.authorize 1
acc.authdb /etc/xrootd/Authfile
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

A=davs://localhost:8443/webdav B=davs://localhost:8444/webdav X=davs://localhost:8445/srv/x
https() { echo "${1/davs:/https:}"; }
for url in $A $B $X; do
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

echo
echo "$pass passed, $fail failed"
if [ $fail -gt 0 ]; then
	for log in $W/weed-a.log $W/weed-b.log $(find $XRD -name xrootd.log); do
		echo "--- tail $log"
		tail -30 $log
	done
	exit 1
fi
