#!/bin/bash
# Runs in the weed-interop container, in a pod with the storage system $STORAGE (see
# storage.sh): weed (A) and the system copy a file to each other, each of them pulling
# and pushing, as gfal2 asks them to with an X.509 proxy and the macaroons that it gets
# from the other side. test.env gives
#   STORAGE_URL   the davs:// directory of the system that the test user may write to
#   WEED_TPC      lines added to weed's [tpc], such as allow_http = true
#   VOMS          a VO: gfal2 acts with a VOMS proxy of that VO rather than a plain one
#   READY_TIMEOUT how long the system may take to start, in seconds (default 300)
set -uo pipefail
W=/work
mkdir -p $W && cd $W || exit 1
. "$(dirname "$0")/lib.sh"

cp /pki/ca.pem /pki/*.r0 /pki/*.namespaces /pki/*.signing_policy /pki/host.pem /pki/host.key /pki/proxy.pem /pki/proxy.key /pki/user.pem /pki/user.key .
# /pki is readable by every container's account; the keys here are not
chmod 600 *.key
use_pki
if [ -n "${VOMS:-}" ] && ! out=$(make_voms_proxy "$VOMS"); then
	echo "FAIL  no VOMS proxy of the VO $VOMS"
	echo "$out" | sed 's/^/      | /'
	exit 1
fi
useradd -M -u 7001 interop
printf '"%s" interop\n' "$USER_DN" >gridmap
mkdir -p /srv/a && chown interop: /srv/a
# The pod's hostname is on a private address (storage.sh)
ISSUERS= start_weed a 8443 'allow_private = true' "${WEED_TPC:-}"

A=davs://localhost:8443/webdav S=$STORAGE_URL
https() { echo "${1/davs:/https:}"; }
CURL="curl -sS --capath $CERTS --cert $X509_USER_PROXY --key $X509_USER_PROXY"
TPC=(-D "HTTP PLUGIN:ENABLE_FALLBACK_TPC_COPY=false")

for i in $(seq 50); do
	curl -s -o /dev/null --capath $CERTS "$(https $A)/" && break
	sleep 0.2
done
echo "waiting for $STORAGE at $S"
start=$SECONDS
until [ "$($CURL -s -L -o /dev/null -w '%{http_code}' -X PROPFIND -H 'Depth: 0' "$(https $S)/" 2>/dev/null)" = 207 ]; do
	if [ $((SECONDS - start)) -gt "${READY_TIMEOUT:-300}" ]; then
		echo "FAIL  $STORAGE did not answer PROPFIND $S/ with 207 within ${READY_TIMEOUT:-300} s"
		$CURL -i -L -X PROPFIND -H 'Depth: 0' "$(https $S)/" 2>&1 | head -20 | sed 's/^/      | /'
		exit 1
	fi
	sleep 2
done
echo "$STORAGE is up after $((SECONDS - start)) s"

# More than socket buffers hold, so that a server that stops reading is noticed
head -c 5000000 /dev/urandom >f.bin
install -o interop -m 644 f.bin /srv/a/f.bin
got() { # url: downloads it with gfal2 and compares it with f.bin
	rm -f got.bin && gfal-copy -f "$1" file://$W/got.bin && cmp f.bin got.bin
}

SUM=$(python3 -c 'import sys, zlib; print("%08x" % zlib.adler32(open(sys.argv[1], "rb").read()))' f.bin)

echo "== $STORAGE with gfal2"
check "upload to $STORAGE" gfal-copy -f -K ADLER32 file://$W/f.bin $S/up.bin
check "download from $STORAGE" got $S/up.bin
check "$STORAGE's adler32" sh -c "gfal-sum $S/up.bin ADLER32 | grep -q ' $SUM\$'"

echo "== third-party copies between weed and $STORAGE"
# The active endpoint is the destination of a pull, and the source of a push
check "$STORAGE pulls from weed" gfal-copy -f --copy-mode pull "${TPC[@]}" -K ADLER32 $A/f.bin $S/pulled.bin
check "$STORAGE's pulled copy matches" got $S/pulled.bin
check "weed pushes to $STORAGE" gfal-copy -f --copy-mode push "${TPC[@]}" -K ADLER32 $A/f.bin $S/pushed.bin
check "$STORAGE's pushed copy matches" got $S/pushed.bin
check "weed pulls from $STORAGE" gfal-copy -f --copy-mode pull "${TPC[@]}" -K ADLER32 $S/up.bin $A/pulled.bin
check "weed's pulled copy matches" cmp f.bin /srv/a/pulled.bin
check "$STORAGE pushes to weed" gfal-copy -f --copy-mode push "${TPC[@]}" -K ADLER32 $S/up.bin $A/pushed.bin
check "weed's pushed copy matches" cmp f.bin /srv/a/pushed.bin

# What the checks left there
left=()
for f in up pulled pushed; do
	gfal-stat $S/$f.bin >/dev/null 2>&1 && left+=($S/$f.bin)
done
[ ${#left[@]} = 0 ] || check "remove from $STORAGE" gfal-rm "${left[@]}"

echo
echo "$pass passed, $fail failed"
if [ $fail -gt 0 ]; then
	echo "--- tail $W/weed-a.log"
	tail -30 $W/weed-a.log
	exit 1
fi
