#!/bin/bash
# The container of make find-limits-users (see users.sh): weed serving USERS accounts
# (user001, ...) that authenticate with WLCG tokens from a test issuer, with a cgroup
# per worker and its own limits alone, which the machine's should come before; then
# stress, with the arguments, which a SIGINT or SIGTERM stops as Ctrl-C does
set -u
L=/limits
N=${USERS:-100}
mkdir -p $L/pki $L/tokens /etc/weed /run/weed /var/lib/weed /var/log/weed
cd $L/pki

# --- Accounts, each with its directory
i=0
for u in $(seq -f 'user%03g' 1 "$N"); do
	i=$((i + 1))
	useradd -M -u $((10000 + i)) $u
	mkdir /data/$u && chown $u: /data/$u
	echo $u >>$L/accounts
done
chmod 755 /data

# --- A CA, and weed's host certificate (localhost)
ssl() { openssl "$@" 2>/dev/null; }
ssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 7 -subj "/DC=org/DC=weed/CN=find-limits CA" \
	-addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
ssl req -newkey rsa:2048 -nodes -keyout host.key -out host.csr -subj "/DC=org/DC=weed/CN=localhost"
ssl x509 -req -in host.csr -CA ca.pem -CAkey ca.key -set_serial 2 -days 7 -out host.pem -extfile <(printf \
	"subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")

# --- WLCG tokens of an hour and a half, minted again every hour, which name each
# account by subject
ssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out issuer.key
ISS=https://localhost:8446
issuer serve -url $ISS -signing-key issuer.key -cert host.pem -key host.key 2>/var/log/issuer.log &
rules=$(awk '{printf "%s{\"sub\": \"%s\", \"user\": \"%s\"}", sep, $1, $1; sep = ", "}' $L/accounts)
printf '[{"issuer": "%s", "audiences": ["https://localhost:9443"], "users": [%s]}]\n' $ISS "$rules" >/etc/weed/issuers.json
mint_tokens() {
	for u in $(cat $L/accounts); do
		issuer mint -url $ISS -signing-key issuer.key -aud https://localhost:9443 \
			-scope "storage.read:/$u storage.modify:/$u" -sub $u -lifetime 90m >$L/tokens/$u.new &&
			mv $L/tokens/$u.new $L/tokens/$u
	done
}
mint_tokens
# By the clock, which moves on while a laptop sleeps and sleep(1) does not
(while sleep 60; do [ -z "$(find $L/tokens/user001 -mmin +60)" ] || mint_tokens; done) &
while read -r u; do echo "$u bearer @$L/tokens/$u"; done <$L/accounts >$L/identities

(umask 077 && cat >/etc/weed/weed.toml) <<T
[server]
port = 9443
dir = "/data"
log_file = "/var/log/weed/weed.log"
# published on the host's loopback only (users.sh)
metrics_address = ":9100"

[tls]
enabled = true
cert = "$L/pki/host.pem"
key = "$L/pki/host.key"

[tokens]
issuers = "/etc/weed/issuers.json"
ca_path = "$L/pki/ca.pem"

[unix_users]
cgroups = true
max_workers = $((N > 256 ? N : 256))
T

# --- weed, in a cgroup delegated to it, as systemd's Delegate=yes gives
cg=/sys/fs/cgroup$(sed 's/^0:://' /proc/self/cgroup)
cg=${cg%/}
mkdir -p $cg/init
for p in $(cat $cg/cgroup.procs); do echo $p >$cg/init/cgroup.procs 2>/dev/null; done
for c in $(cat $cg/cgroup.controllers); do
	case $c in cpu | io | memory | pids) echo +$c >$cg/cgroup.subtree_control ;; esac
done
mkdir -p $cg/weed
weed check -config /etc/weed/weed.toml || exit 1
# A session of its own, which a Ctrl-C on the terminal does not reach
(echo $BASHPID >$cg/weed/cgroup.procs && exec setsid weed -config /etc/weed/weed.toml) &
weed=$!

# weed reopens its log on SIGHUP, which also reloads it
(while sleep 60; do
	if [ "$(stat -c %s /var/log/weed/weed.log)" -gt 200000000 ]; then
		mv /var/log/weed/weed.log /var/log/weed/weed.log.1 && kill -HUP $weed
	fi
done) &

i=0
until curl -sf -o /dev/null localhost:9100/healthz; do
	i=$((i + 1))
	if ! kill -0 $weed 2>/dev/null || [ $i = 300 ]; then
		tail -30 /var/log/weed/weed.log
		echo "find-limits-users: weed did not start"
		exit 1
	fi
	sleep 1
done
cat <<EOF
find-limits-users: weed serves $N accounts, from a volume of $(df -h --output=avail /data | tail -1 | tr -d ' ') available,
and its dashboard at http://127.0.0.1:$METRICS_PORT/dashboard/. Ctrl-C stops the load.

EOF
stress -identities $L/identities -url 'https://localhost:9443/webdav/{user}' -ca $L/pki/ca.pem \
	-cgroup $cg/weed -status http://localhost:9100/status -report $L/limits.txt -json $L/limits.json "$@" &
stress=$!
trap 'kill -INT $stress 2>/dev/null' INT TERM
# wait returns at a signal, and stress, which then reports what it measured, after
while wait $stress; status=$?; kill -0 $stress 2>/dev/null; do :; done
exit $status
