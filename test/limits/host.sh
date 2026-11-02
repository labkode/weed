#!/bin/sh
# make find-limits: the limits of weed on this machine, serving one account, under a
# load that grows until weed or the machine gives (test/stress): small files read,
# written and listed, new TLS connections, downloads and uploads of large files, and
# each authentication method. weed runs as root in a unit of its own (systemd-run),
# whose cgroup stress reports the CPU and memory of, with TLS, a cgroup per worker,
# Landlock and seccomp; the account, yours or ACCOUNT=, authenticates with an X.509
# certificate, a WLCG token from a test issuer and a password. Its credentials and
# configuration are in a temporary directory: the machine keeps no change. The
# arguments go to stress (stress -h), e.g. -scenarios download; the results are in
# test/limits/out. Needs Go, openssl, systemd and sudo.
#
# weed's files are in a directory of DATA (/var/tmp), the storage that is measured,
# which upload fills with up to 256 × 64 MiB (stress -max and -upload-size). PORT
# (9443) and METRICS_PORT (9100), on 127.0.0.1, serve weed and its dashboard.
#
#     [ACCOUNT=name] [DATA=dir] test/limits/host.sh [stress arguments]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
fail() { echo "find-limits: $*" >&2; exit 1; }

account=${ACCOUNT:-${SUDO_USER:-$(id -un)}}
uid=$(id -u "$account" 2>/dev/null) || fail "there is no account $account"
[ "$uid" != 0 ] || fail "weed serves no request as root: ACCOUNT= names an account"
port=${PORT:-9443}
metrics=${METRICS_PORT:-9100}
unit=weed-find-limits
out=$here/out
command -v systemd-run >/dev/null || fail "weed runs in a unit of its own: this needs systemd"
command -v openssl >/dev/null || fail "the credentials are made with openssl, which is not installed"
! systemctl is-active -q $unit || fail "$unit runs already: sudo systemctl stop $unit"
echo "find-limits: weed runs as root (sudo)"
sudo -v

work=$(mktemp -d) # binaries, credentials, the configuration and weed's log
data=$(mktemp -d -p "${DATA:-/var/tmp}" weed-find-limits.XXXXXX)
pids=
cleanup() {
	for p in $pids; do kill "$p" 2>/dev/null || true; done
	sudo systemctl stop $unit 2>/dev/null || true
	sudo rm -rf -- "$work" "$data"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "find-limits: building weed, test/stress and a token issuer"
(cd "$root" && go build -trimpath -o "$work/weed" . && go build -o "$work/stress" ./test/stress &&
	go build -o "$work/issuer" ./test/interop/issuer)
cd "$work"

# --- A CA with an empty CRL, weed's host certificate, the account's certificate
ssl() { openssl "$@" 2>/dev/null; }
mkdir certificates
ssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 7 -subj "/DC=org/DC=weed/CN=find-limits CA" \
	-addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
hash=$(openssl x509 -hash -noout -in ca.pem)
cp ca.pem certificates/$hash.0
issue() { # name subject serial extensions
	printf "$4" >$1.ext
	ssl req -newkey rsa:2048 -nodes -keyout $1.key -out $1.csr -subj "$2"
	ssl x509 -req -in $1.csr -CA ca.pem -CAkey ca.key -set_serial $3 -days 7 -out $1.pem -extfile $1.ext
}
issue host "/DC=org/DC=weed/CN=localhost" 2 \
	"subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n"
dn="/DC=org/DC=weed/OU=Users/CN=$account"
issue user "$dn" 3 "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n"
printf '"%s" %s\n' "$dn" "$account" >grid-mapfile
mkdir crl && touch crl/index.txt && echo 01 >crl/crlnumber
printf '[ca]\ndefault_ca = d\n[d]\ndatabase = crl/index.txt\ncrlnumber = crl/crlnumber\ndefault_md = sha256\ndefault_crl_days = 7\n' >crl.cnf
ssl ca -config crl.cnf -gencrl -keyfile ca.key -cert ca.pem -out certificates/$hash.r0

# --- A password, and WLCG tokens of an hour and a half, minted again every hour
password=$(openssl rand -hex 16)
./weed utils password "$account" "$password" >/dev/null && chmod 600 .htpasswd
ssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out issuer.key
iss=https://localhost:$((port + 1))
./issuer serve -url $iss -signing-key issuer.key -cert host.pem -key host.key 2>issuer.log &
pids="$pids $!"
printf '[{"issuer": "%s", "audiences": ["https://localhost:%s"], "users": [{"sub": "%s", "user": "%s"}]}]\n' \
	$iss $port "$account" "$account" >issuers.json
mint() {
	./issuer mint -url $iss -signing-key issuer.key -aud https://localhost:$port \
		-scope "storage.read:/$account storage.modify:/$account" -sub "$account" -lifetime 90m >token.new &&
		mv token.new token
}
mint
# By the clock, which moves on while a laptop sleeps and sleep(1) does not
(while sleep 60; do [ -z "$(find token -mmin +60)" ] || mint; done) &
pids="$pids $!"
cat >identities <<EOF
$account cert $work/user.pem $work/user.key
$account bearer @$work/token
$account basic $password
EOF

# --- weed, its own limits alone, which the machine's should come before
chmod 755 "$data"
sudo install -d -o "$account" -g "$(id -g "$account")" -m 0755 "$data/$account"
cat >weed.toml <<EOF
[server]
address = "127.0.0.1"
port = $port
dir = "$data"
log_file = "$work/weed.log"
metrics_address = "127.0.0.1:$metrics"

[tls]
enabled = true
cert = "$work/host.pem"
key = "$work/host.key"

[x509]
enabled = true
ca = "$work/certificates"
crl_path = "$work/certificates"
gridmap = "$work/grid-mapfile"

[basic]
enabled = true
htpasswd = "$work/.htpasswd"
app_tokens = "$work/.app-tokens"

[tokens]
issuers = "$work/issuers.json"
ca_path = "$work/ca.pem"

[unix_users]
cgroups = true

[admin]
socket = "$work/admin.sock"
bans = "$work/bans"
EOF
sudo ./weed check -config weed.toml
sudo systemd-run --quiet --unit=$unit --collect -p Type=notify -p Delegate=yes "$work/weed" -config "$work/weed.toml" || {
	sudo journalctl -u $unit -n 20 --no-pager -o cat >&2
	sudo tail -20 weed.log >&2
	fail "weed did not start"
}
cg=/sys/fs/cgroup$(systemctl show -P ControlGroup $unit)
# weed reopens its log on SIGHUP, which also reloads it
sudo sh -c "while sleep 60; do
	if [ \"\$(stat -c %s $work/weed.log)\" -gt 200000000 ]; then
		mv $work/weed.log $work/weed.log.1 && systemctl kill --kill-whom=main -s HUP $unit
	fi
done" &
pids="$pids $!"

cat <<EOF
find-limits: weed serves $account at https://127.0.0.1:$port/webdav/$account, from
$data ($(df -h --output=avail "$data" | tail -1 | tr -d ' ') available), and its dashboard at
http://127.0.0.1:$metrics/dashboard/. Ctrl-C stops the load, and cleans up.

EOF
mkdir -p "$out"
status=0
./stress -identities identities -url "https://127.0.0.1:$port/webdav/$account" -ca ca.pem \
	-cgroup "$cg" -status "http://127.0.0.1:$metrics/status" \
	-report "$out/find-limits.txt" -json "$out/find-limits.json" \
	-scenarios get-small,put-small,list,connect,download,upload,auth "$@" || status=$?
echo
echo "find-limits: the results are in ${out#"$root"/}/find-limits.txt and find-limits.json"
exit $status
