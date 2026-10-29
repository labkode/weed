#!/bin/bash
# Runs inside the weed-lab container (see lab.sh): one weed whose 22 Unix accounts
# authenticate with certificates, WLCG tokens and passwords, with limits per account
# and group, and a load that does not stop (load.sh)
set -u
L=/lab
mkdir -p $L/pki $L/tokens $L/files /etc/weed /run/weed /var/lib/weed /var/log/weed
cd $L/pki

# --- Accounts: name kind uid group
ACCOUNTS="alice:x509:6001: bob:x509:6002: carol:x509:6003:
dave:basic:6004: erin:basic:6005: frank:basic:6006:
atlas001:token:6101:atlas atlas002:token:6102:atlas atlas003:token:6103:atlas
atlas004:token:6104:atlas atlas005:token:6105:atlas atlas006:token:6106:atlas
cms001:token:6201:cms cms002:token:6202:cms cms003:token:6203:cms cms004:token:6204:cms
cms005:token:6205:cms cmsprod:token:6210:cms
lhcb001:basic:6301:lhcb lhcb002:basic:6302:lhcb lhcb003:basic:6303:lhcb lhcb004:basic:6304:lhcb"
groupadd -g 6100 atlas; groupadd -g 6200 cms; groupadd -g 6300 lhcb
for a in $ACCOUNTS; do
	IFS=: read -r name kind uid group <<<"$a"
	useradd -M -u $uid ${group:+-G $group} $name
	mkdir -p /data/$name && chown $name: /data/$name
	echo "$name $kind" >>$L/accounts
done
chmod 755 /data

# --- PKI: a CA with a CRL, the host certificate (localhost), user certificates
ssl() { openssl "$@" 2>/dev/null; }
CERTS=/etc/grid-security/certificates
mkdir -p $CERTS
ssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 -subj "/DC=org/DC=weed/CN=Lab CA" \
	-addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
hash=$(openssl x509 -hash -noout -in ca.pem)
cp ca.pem $CERTS/$hash.0
issue() { # name subject serial extensions
	ssl req -newkey rsa:2048 -nodes -keyout $1.key -out $1.csr -subj "$2"
	ssl x509 -req -in $1.csr -CA ca.pem -CAkey ca.key -set_serial $3 -days 30 -out $1.pem -extfile <(printf "$4")
}
issue host "/DC=org/DC=weed/CN=localhost" 2 \
	"subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n"
serial=10
for u in alice bob carol mallory; do
	issue $u "/DC=org/DC=weed/OU=Users/CN=$u" $serial "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n"
	serial=$((serial + 1))
	[ $u != mallory ] && echo "\"/DC=org/DC=weed/OU=Users/CN=$u\" $u" >>/etc/grid-security/grid-mapfile
done
mkdir -p ca && touch ca/index.txt && echo 01 >ca/crlnumber
printf '[ca]\ndefault_ca = d\n[d]\ndatabase = ca/index.txt\ncrlnumber = ca/crlnumber\ndefault_md = sha256\ndefault_crl_days = 30\n' >ca.cnf
ssl ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.pem -out $CERTS/$hash.r0

# --- WLCG token issuer: tokens name atlas and cms accounts by subject, cmsprod by group
ssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out issuer.key
ISS=https://localhost:8446
issuer serve -url $ISS -signing-key issuer.key -cert host.pem -key host.key 2>/var/log/issuer.log &
rules=$(awk '$2 == "token" && $1 != "cmsprod" {printf "%s{\"sub\": \"%s\", \"user\": \"%s\"}", sep, $1, $1; sep = ", "}' $L/accounts)
printf '[{"issuer": "%s", "audiences": ["https://localhost:9443"], "users": [%s, {"group": "/cms/production", "user": "cmsprod"}]}]\n' \
	$ISS "$rules" >/etc/weed/issuers.json
mint_tokens() { # every hour, tokens of an hour and a half
	for u in $(awk '$2 == "token" {print $1}' $L/accounts); do
		if [ $u = cmsprod ]; then who=(-sub cms-production-robot -groups /cms/production); else who=(-sub $u); fi
		issuer mint -url $ISS -signing-key issuer.key -aud https://localhost:9443 \
			-scope "storage.read:/$u storage.modify:/$u" "${who[@]}" -lifetime 90m >$L/tokens/$u.new &&
			mv $L/tokens/$u.new $L/tokens/$u
	done
	issuer mint -url $ISS -signing-key issuer.key -aud https://localhost:9443 -scope "storage.read:/atlas001" \
		-sub atlas001 -lifetime -1h >$L/tokens/expired
}
mint_tokens
(while sleep 3600; do mint_tokens; done) &

# --- Passwords: lab-<account>
cd /etc/weed
for u in $(awk '$2 == "basic" {print $1}' $L/accounts); do weed utils password $u lab-$u >/dev/null; done
chmod 600 .htpasswd

# --- Limits: totals of 120 MB/s out and 60 MB/s in, shared by weight
cat >limits.json <<'J'
[
  {"user": "cmsprod", "weight": 1000, "egress_rate": "max", "ingress_rate": "max"},
  {"user": "alice", "ingress_rate": "5MB/s"},
  {"user": "frank", "cgroup_limits": ["memory.max=384M"]},
  {"group": "cms", "cgroup_limits": ["memory.max=1G", "cpu.weight=300"], "weight": 300},
  {"group": "atlas", "cgroup_limits": ["cpu.weight=200"], "weight": 200},
  {"group": "lhcb", "weight": 50, "egress_rate": "10MB/s", "ingress_rate": "5MB/s"}
]
J
(umask 077 && cat >weed.toml) <<T
[server]
port = 9443
dir = "/data"
log_file = "/var/log/weed/weed.log"
# published on the host's loopback only (up.sh)
metrics_address = ":9100"
reload_interval = "10m"

[tls]
enabled = true
cert = "$L/pki/host.pem"
key = "$L/pki/host.key"

[x509]
enabled = true
ca = "$CERTS"
crl_path = "$CERTS"

[basic]
enabled = true
htpasswd = "/etc/weed/.htpasswd"
app_tokens = "/etc/weed/.app-tokens"

[macaroons]
enabled = true
secret_key = "$(openssl rand -hex 32)"

[tokens]
issuers = "/etc/weed/issuers.json"
ca_path = "$L/pki/ca.pem"

[tpc]
enabled = true
ca_path = "$L/pki/ca.pem"
allow_http = true
allow_local = true

[unix_users]
idle_timeout = "90s"
max_requests = 200
cgroup_limits = ["memory.max=512M", "pids.max=1000"]
limits = "/etc/weed/limits.json"

[network]
egress_rate = "120MB/s"
ingress_rate = "60MB/s"
account_egress_rate = "40MB/s"
account_ingress_rate = "20MB/s"
T

# --- Files that clients upload, and that third-party copies pull over plain HTTP
for s in 4k:4 64k:64 256k:256 1m:1024 4m:4096 16m:16384 32m:32768; do
	head -c $((${s#*:} * 1024)) /dev/urandom >$L/files/${s%:*}
done
python3 -m http.server 8080 --bind 127.0.0.1 --directory $L/files >/dev/null 2>&1 &

# --- weed, in a cgroup delegated to it, as systemd's Delegate=yes gives
cg=/sys/fs/cgroup$(sed 's/^0:://' /proc/self/cgroup)
mkdir -p $cg/init
for p in $(cat $cg/cgroup.procs); do echo $p >$cg/init/cgroup.procs 2>/dev/null; done
echo "+cpu +io +memory +pids" >$cg/cgroup.subtree_control
mkdir -p $cg/weed
weed check -config /etc/weed/weed.toml || exit 1
(echo $BASHPID >$cg/weed/cgroup.procs && exec weed -config /etc/weed/weed.toml) &
weed=$!
for i in $(seq 50); do curl -sf -o /dev/null localhost:9100/healthz && break; sleep 0.2; done
echo "weed is up (pid $weed): the load starts"

# weed reopens its log on SIGHUP, which also reloads it
(while sleep 60; do
	if [ "$(stat -c %s /var/log/weed/weed.log)" -gt 200000000 ]; then
		mv /var/log/weed/weed.log /var/log/weed/weed.log.1 && kill -HUP $weed
	fi
done) &

# The shell of make lab-ssh
cat >/lab/motd <<'M'
weed lab: weed serves /data at $W to 22 accounts (/lab/accounts) under the load of
/lab/load.sh, whose scenes /var/log/lab.log tells. weed logs to /var/log/weed/weed.log.

  as alice $W/alice/ -X PROPFIND -H 'Depth: 1'   curl with an account's credentials
  curl -s localhost:9100/status | jq .network     also /metrics and /healthz
  ps -o user,pid,rss,args -C weed                 weed and its workers
  cat /sys/fs/cgroup/weed/worker-cms001/memory.max
  weed utils ban -reason test frank               then weed utils bans, unban frank
  vi /etc/weed/limits.json; pkill -HUP -o -x weed reload, with the new limits
M
cat >>/root/.bashrc <<'B'
W=https://localhost:9443/webdav CA=/lab/pki/ca.pem
. /lab/creds.sh
# as ACCOUNT ARGS...: curl with the account's credentials
as() { auth_of "$1" || return; shift; curl -s --cacert $CA "${A[@]}" "$@"; }
cat /lab/motd
B

bash /lab/load.sh 2>&1 | tee /var/log/lab.log &
wait $weed
echo "weed exited ($?)"
