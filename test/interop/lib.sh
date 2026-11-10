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
# make_pki: the CA and the certificates, in the current directory. In the storage tests'
# pod the host certificate also names the pod's address, which XRootD redirects clients
# to rather than its name, the address being a private one
make_pki() {
	local san="DNS:localhost,IP:127.0.0.1,IP:::1,DNS:$POD_HOST" ip
	ip=$(getent ahostsv4 $POD_HOST 2>/dev/null | awk 'NR == 1 { print $1 }')
	[ -z "$ip" ] || san="$san,IP:$ip"
	ssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/DC=org/DC=weed/CN=Interop CA" \
		-addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
	issue host "/DC=org/DC=weed/CN=localhost" ca.pem ca.key 2 \
		"subjectAltName=$san\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n"
	issue user "$USER_DN" ca.pem ca.key 3 "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n"
	issue proxy "$USER_DN/CN=1234567" user.pem user.key 1234567 \
		"keyUsage=critical,digitalSignature,keyEncipherment\nproxyCertInfo=critical,language:id-ppl-inheritAll\n"
	# The namespaces that IGTF CAs come with, which StoRM and dCache require
	local h
	h=$(openssl x509 -hash -noout -in ca.pem)
	printf 'TO Issuer "/DC=org/DC=weed/CN=Interop CA" \\\n  PERMIT Subject "/DC=org/DC=weed/.*"\n' >$h.namespaces
	printf "access_id_CA X509 '/DC=org/DC=weed/CN=Interop CA'\npos_rights globus CA:sign\ncond_subjects globus '\"/DC=org/DC=weed/*\"'\n" >$h.signing_policy
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
	cp *.r0 *.namespaces *.signing_policy $CERTS/
	cat proxy.pem proxy.key user.pem >/tmp/x509up_u0
	chmod 600 /tmp/x509up_u0
	export X509_USER_PROXY=/tmp/x509up_u0 X509_CERT_DIR=$CERTS
}

# make_voms_proxy vo: a VOMS proxy in place of the RFC 3820 proxy, with the attribute
# /<vo>, signed by the host certificate as the VO's server, localhost:15000 (no server
# runs there: an LSC file, which names its DN and its CA's, is all a storage needs)
make_voms_proxy() {
	local out
	out=$(voms-proxy-fake -cert user.pem -key user.key -hostcert host.pem -hostkey host.key -voms $1 \
		-fqan /$1/Role=NULL/Capability=NULL -uri localhost:15000 -rfc -out $X509_USER_PROXY 2>&1) || {
		echo "$out" | tail -5
		return 1
	}
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
