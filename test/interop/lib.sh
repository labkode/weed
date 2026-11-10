# Shared by the interoperability tests that run in the weed-interop container: run.sh,
# and storage/run.sh against other storage systems (see interop.sh and storage.sh).
# Sourced, in the working directory $W.

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

# --- PKI: CA, host certificate, user certificate, RFC 3820 proxy
CERTS=/etc/grid-security/certificates
USER_DN="/DC=org/DC=weed/OU=Users/CN=Interop User"
# The storage tests' pod has this name, which redirectors send clients to (storage.sh)
POD_HOST=storage.interop.test
ssl() { openssl "$@" 2>/dev/null; }
issue() { # name subject signer-cert signer-key serial extensions
	ssl req -newkey rsa:2048 -nodes -keyout $1.key -out $1.csr -subj "$2"
	ssl x509 -req -in $1.csr -CA $3 -CAkey $4 -set_serial $5 -days 1 -out $1.pem -extfile <(printf "$6")
}
# make_pki: the CA and the certificates, in the current directory
make_pki() {
	ssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/DC=org/DC=weed/CN=Interop CA" \
		-addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
	issue host "/DC=org/DC=weed/CN=localhost" ca.pem ca.key 2 \
		"subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1,DNS:$POD_HOST\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n"
	issue user "$USER_DN" ca.pem ca.key 3 "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n"
	issue proxy "$USER_DN/CN=1234567" user.pem user.key 1234567 \
		"keyUsage=critical,digitalSignature,keyEncipherment\nproxyCertInfo=critical,language:id-ppl-inheritAll\n"
	mkdir -p ca && touch ca/index.txt && echo 01 >ca/crlnumber
	printf '[ca]\ndefault_ca = d\n[d]\ndatabase = ca/index.txt\ncrlnumber = ca/crlnumber\ndefault_md = sha256\ndefault_crl_days = 1\n' >ca.cnf
	gencrl .
}
# gencrl [dir]: the CA's CRL, of the certificates revoked so far, made by openssl and
# installed the way fetch-crl does (<hash>.r0), in $CERTS or dir
gencrl() { ssl ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.pem -out ${1:-$CERTS}/$(openssl x509 -hash -noout -in ca.pem).r0; }
# use_pki: trust the CA, and act with the proxy
use_pki() {
	mkdir -p $CERTS
	cp ca.pem $CERTS/$(openssl x509 -hash -noout -in ca.pem).0
	cp *.r0 $CERTS/
	cat proxy.pem proxy.key user.pem >/tmp/x509up_u0
	chmod 600 /tmp/x509up_u0
	export X509_USER_PROXY=/tmp/x509up_u0 X509_CERT_DIR=$CERTS
}

# start_weed name port [lines appended to its configuration, after [tpc]]: weed serving
# /srv/<name> with host.pem, the gridmap file and, unless ISSUERS is set to "", tokens
# from the issuers of issuers.json; METRICS, ISSUERS, LOG_FORMAT
start_weed() {
	(umask 077 && cat >weed-$1.toml) <<TOML
[server]
port = $2
dir = "/srv/$1"
log_file = "$W/weed-$1.log"
log_format = "${LOG_FORMAT:-text}"
metrics_address = "${METRICS:-}"
[admin]
socket = "/run/weed/$1.sock"
bans = "$W/bans-$1.json"
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
$([ -n "${ISSUERS-issuers.json}" ] && printf '[tokens]\nissuers = "%s"\nca_path = "ca.pem"' "${ISSUERS-issuers.json}")
[tpc]
enabled = true
ca_path = "$CERTS"
allow_local = true
marker_interval = "20ms"
TOML
	printf '%s\n' "${@:3}" >>weed-$1.toml
	weed -config weed-$1.toml &
}
