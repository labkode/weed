#!/bin/bash
# Runs inside the weed-systemd container (see systemd.sh), whose PID 1 is systemd: weed
# as the service of the guide (/test/installation.md, from docs/src), its unit with
# Delegate=yes and the sandboxing that the guide suggests, as root and then as an
# account of its own with the capabilities of the guide
set -uo pipefail

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

# block TEXT: the code block of the guide that follows the line holding TEXT
block() {
	TEXT=$1 awk '
		!found { found = index($0, ENVIRON["TEXT"]) > 0; next }
		/^    / { print substr($0, 5); got = 1; next }
		/^$/ { if (got) print; next }
		got { exit }
	' /test/installation.md
}

# --- The service, as the guide writes it
block 'Write /etc/systemd/system/weed.service:' >/etc/systemd/system/weed.service
mkdir -p /etc/systemd/system/weed.service.d
{
	echo '[Service]'
	echo 'Delegate=yes'
	block 'For instance, in \[Service\]:'
} >/etc/systemd/system/weed.service.d/sandbox.conf
check "the guide has the unit, and its sandboxing" sh -c "grep -q '^ExecStart=/usr/local/bin/weed' /etc/systemd/system/weed.service &&
	grep -q '^OOMPolicy=continue' /etc/systemd/system/weed.service &&
	grep -q '^ProtectSystem=strict' /etc/systemd/system/weed.service.d/sandbox.conf"

# --- Two accounts, which log in with passwords; bob not yet
useradd -M -u 6001 alice
useradd -M -u 6002 bob
mkdir -p /data/alice /data/bob && chown alice: /data/alice && chown bob: /data/bob
mkdir -m 0755 /etc/weed && cd /etc/weed && weed utils password alice pw-alice >/dev/null && chmod 600 .htpasswd
cat >/etc/weed/weed.toml <<'T'
[server]
port = 8080
dir = "/data"
metrics_address = "127.0.0.1:9100"

[basic]
enabled = true
htpasswd = "/etc/weed/.htpasswd"

[tpc]
enabled = true
allow_http = true
allow_local = true

[unix_users]
cgroups = true
T
cd /
W=http://127.0.0.1:8080/webdav
CG=/sys/fs/cgroup/system.slice/weed.service
as() { # as ACCOUNT ARGS...: curl with the account's password
	local u=$1
	shift
	curl -sS --fail-with-body -u "$u:pw-$u" "$@"
}
main() { systemctl show -P MainPID weed; }

t_upload() { # the file belongs to alice
	as alice -T /etc/os-release $W/alice/$1 && [ "$(stat -c %U /data/alice/$1)" = alice ]
}
t_get() { as alice $W/alice/f | cmp - /etc/os-release; }
t_cgroup() { # weed in <its cgroup>/main, alice's worker in worker-alice
	local w
	grep -qx "$(main)" $CG/main/cgroup.procs && w=$(head -1 $CG/worker-alice/cgroup.procs) &&
		[ -n "$w" ] && [ "$(ps -o user= -p "$w")" = alice ]
}
t_ban() { # through admin.socket, in RuntimeDirectory; the bans in StateDirectory; alice's file $1
	weed utils ban -reason test alice && ! as alice -o /dev/null $W/alice/$1 &&
		grep -q alice /var/lib/weed/bans.json &&
		weed utils unban alice && as alice -o /dev/null $W/alice/$1
}
t_readonly() { ! nsenter -t "$(main)" -m touch /etc/weed/probe; }
t_writable() {
	nsenter -t "$(main)" -m sh -c 'touch /data/probe /run/weed/probe /var/lib/weed/probe &&
		rm /data/probe /run/weed/probe /var/lib/weed/probe'
}
t_home() { [ -n "$(ls -A /root)" ] && [ -z "$(nsenter -t "$(main)" -m ls -A /root)" ]; }
t_tpc() { # the worker connects to weed, as to another server
	as alice -X COPY -H "Source: $W/alice/f" -H "TransferHeaderAuthorization: Basic $(printf alice:pw-alice | base64)" \
		$W/alice/g | tail -1 | grep '^success' && cmp /data/alice/f /data/alice/g
}
t_refused() { ! as bob -T /etc/os-release $W/bob/f; }
t_reload() {
	(cd /etc/weed && weed utils password bob pw-bob >/dev/null) && systemctl reload weed &&
		as bob -T /etc/os-release $W/bob/f
}
serving() { # a weed other than $1 serves: within 90 s, as systemd restarts it ever less often
	local p
	for i in $(seq 180); do
		p=$(main)
		[ "$p" != 0 ] && [ "$p" != "$1" ] && curl -sf 127.0.0.1:9100/healthz >/dev/null && return 0
		sleep 0.5
	done
	return 1
}
now() { date '+%Y-%m-%d %H:%M:%S'; }
# logged SINCE PATTERN; grep reads it all: with pipefail, grep -q could fail journalctl
logged() { journalctl -u weed -o cat --since "$1" | grep "$2" >/dev/null; }
t_user() { [ "$(ps -o user= -p "$(main)")" = "$1" ]; }
t_confined() { # weed executed itself again confined: no_new_privs, which it sets to be
	grep -qx 'NoNewPrivs:	1' /proc/"$(main)"/status && journalctl -u weed -o cat | grep 'weed confines itself with Landlock'
}
code() { as "$@" -o /dev/null -w '%{http_code}' 2>/dev/null; }
storage() { # mounts a storage of its own at /data, as for a remount
	mount -t tmpfs storage /data && mkdir /data/alice && chown alice: /data/alice
}
t_moved() { # weed $1 exited (status 75) after $2, and systemd started another
	serving "$1" && logged "$2" 'weed exits, to be started again by its supervisor' && logged "$2" 'status=75' ||
		{ journalctl -u weed -o cat --since "$2" | grep -E 'exit|status=|may no longer|confine workers|Stopp|Starting|Main process' | cut -c1-300; return 1; }
}
t_serves() { # alice's upload lands in the storage now at /data
	for i in $(seq 180); do
		[ "$(code alice -T /etc/os-release $W/alice/$1)" = 201 ] && [ -e /data/alice/$1 ] && return 0
		sleep 0.5
	done
	return 1
}
t_blocked() { # weed $1, its storage unmounted after $2, refuses requests and goes on running
	for i in $(seq 30); do
		[ "$(code alice -T /etc/os-release $W/alice/b)" = 503 ] && break
		sleep 0.5
	done
	[ "$(code alice -T /etc/os-release $W/alice/b)" = 503 ] && [ ! -e /data/alice/b ] &&
		[ "$(curl -s -o /dev/null -w '%{http_code}' 127.0.0.1:9100/healthz)" = 503 ] &&
		logged "$2" 'the storage of the exported directory is no longer mounted' &&
		systemctl show -P StatusText weed | grep '^Blocked since .*, the storage of /data not mounted' &&
		curl -s 127.0.0.1:9100/metrics | grep -x 'weed_storage_unmounted 1' &&
		curl -s 127.0.0.1:9100/status | jq -e .storage_unmounted || return 1
	sleep 6 # a look at the directory more: weed still does not exit
	[ "$(main)" = "$1" ] && [ "$(systemctl show -P ActiveState weed)" = active ]
}
t_not_started() { # restarted while its storage is not mounted, weed does not start, as systemd tries again
	local n since
	since=$(now)
	! systemctl restart weed && logged "$since" 'is on the file system of /, not on a storage of its own' || return 1
	n=$(systemctl show -P NRestarts weed)
	for i in $(seq 180); do
		[ "$(systemctl show -P NRestarts weed)" -gt "$n" ] && break
		sleep 0.5
	done
	[ "$(systemctl show -P NRestarts weed)" -gt "$n" ] && [ "$(systemctl show -P ActiveState weed)" != failed ] &&
		! curl -sf 127.0.0.1:9100/healthz
}
t_require_mount() { systemctl restart weed && t_serves n2; }
t_beneath() { ! as alice -T /etc/os-release $W/alice/q 2>/dev/null && [ ! -e /data/alice/q ]; }
t_oom() { # alice's worker, its memory.max lowered below what it uses, is killed by the kernel: weed goes on
	local pid w kills
	pid=$(main)
	as alice -o /dev/null $W/alice/p && w=$(head -1 $CG/worker-alice/cgroup.procs) && [ -n "$w" ] || return 1
	kills=$(awk '$1 == "oom_kill" {print $2}' $CG/memory.events)
	# Not swapped out instead, where there is swap
	[ -f $CG/worker-alice/memory.swap.max ] && echo 0 >$CG/worker-alice/memory.swap.max
	echo 1M >$CG/worker-alice/memory.max
	for i in $(seq 40); do
		kill -0 "$w" 2>/dev/null || break
		sleep 0.25
	done
	! kill -0 "$w" 2>/dev/null && [ "$(awk '$1 == "oom_kill" {print $2}' $CG/memory.events)" -gt "$kills" ] &&
		[ "$(main)" = "$pid" ] && [ "$(systemctl show -P ActiveState weed)" = active ] && curl -sf 127.0.0.1:9100/healthz ||
		{ echo "worker $w, weed $pid now $(main)"; grep oom $CG/memory.events; ps -o pid,user,rss,args -u alice; return 1; }
}
t_oom_next() { # the account's next request gets a worker again
	[ -f $CG/worker-alice/memory.max ] && echo max >$CG/worker-alice/memory.max
	t_serves oom
}
t_activated() { # the first connection to weed.socket starts weed
	systemctl start weed.socket && [ "$(systemctl show -P ActiveState weed)" = inactive ] &&
		curl -sf --max-time 60 127.0.0.1:9100/healthz && [ "$(systemctl show -P ActiveState weed)" = active ]
}
t_passed() { # weed took the sockets of systemd, and binds no port
	logged "$1" 'msg=listening address=.*:8080 scheme=http socket="passed by systemd"' &&
		logged "$1" 'msg="serving metrics" address=127.0.0.1:9100 socket="passed by systemd"' &&
		logged "$1" 'tcp="no bind' ||
		{ journalctl -u weed -o cat --since "$1" | grep -E 'listening|serving metrics|tcp=' | cut -c1-300; return 1; }
}
t_no_refused() { # requests made while weed restarts wait for it: all succeed
	local codes=/tmp/codes loop
	as alice -T /etc/os-release $W/alice/s || return 1
	: >$codes
	(for i in $(seq 120); do
		code alice $W/alice/s >>$codes
		echo >>$codes
		sleep 0.05
	done) &
	loop=$!
	sleep 1
	systemctl restart weed
	wait $loop
	echo "$(sort $codes | uniq -c | tr '\n' ' ')"
	[ "$(grep -c . $codes)" = 120 ] && ! grep -qvx 200 $codes
}
t_stop() { # weed and its workers stop, and weed exits 0
	systemctl stop weed && [ "$(systemctl show -P Result weed)" = success ] &&
		[ "$(systemctl show -P ExecMainStatus weed)" = 0 ] && ! pgrep -u alice
}

# --- As root
# Mounts made here reach weed's namespace (ProtectSystem=), as on a host, where systemd
# makes / shared; a container's is private
mount --make-rshared /
systemctl daemon-reload
check "weed check accepts the configuration" weed check -config /etc/weed/weed.toml
# Type=notify: systemctl returns once weed says it is ready, and it serves then
check "systemctl start returns once weed serves" sh -c 'systemctl start weed && curl -sf 127.0.0.1:9100/healthz'
check "the status line says since when weed serves" sh -c "systemctl show -P StatusText weed | grep '^Serving since'"
check "weed's log is in the journal: workers confined with Landlock" sh -c "journalctl -u weed -o cat | grep 'workers are confined with Landlock'"
check "weed's own process is confined with Landlock" t_confined
check "alice uploads, and the file is hers" t_upload f
check "a GET gives it back" t_get
check "Delegate=yes: weed runs in main, alice's worker in worker-alice" t_cgroup
check "ProtectSystem=strict: weed may not write /etc" t_readonly
check "...but /data, /run/weed and /var/lib/weed" t_writable
check "ProtectHome=yes: /root is empty to weed" t_home
check "a third-party copy that weed pulls from itself" t_tpc
check "bob, without a password, is refused" t_refused
check "systemctl reload re-reads the passwords: bob's, added, works" t_reload
check "weed utils ban and unban" t_ban f
# A storage mounted over the exported directory, as for a remount: weed, confined to the
# directory as it was, exits, and systemd starts it again confined to the storage
old=$(main) since=$(now)
storage
check "a storage mounted over the exported directory: weed exits, and systemd starts it again" t_moved "$old" "$since"
check "...serving that storage" t_serves n
# Unmounted: weed blocks, never serving the directory beneath, until it is mounted again
old=$(main) since=$(now)
umount /data
check "its storage unmounted, weed blocks: 503, /healthz too, the same weed goes on" t_blocked "$old" "$since"
check "...nor does anything land in the directory beneath" t_beneath
old=$(main) since=$(now)
storage
check "...mounted again: weed exits, and systemd starts it again" t_moved "$old" "$since"
check "...serving that storage" t_serves m
# server.require_mount: nor does a weed that starts while the storage is not mounted
sed -i 's/^\[server\]$/&\nrequire_mount = true/' /etc/weed/weed.toml
check "require_mount: weed serves the storage mounted at the exported directory" t_require_mount
umount /data
check "...restarted while it is not mounted: weed does not start, as systemd tries again" t_not_started
check "...nor does anything land in the directory beneath" t_beneath
storage
check "...mounted again: weed starts, and serves it" t_serves p
check "a worker that the kernel kills for its memory: weed goes on (OOMPolicy=continue)" t_oom
check "...and the account's next request gets a worker" t_oom_next
old=$(main)
[ "$old" != 0 ] && kill -9 "$old" # not 0: the process group of this script
check "Restart=on-failure: a weed that is killed starts again" serving "$old"

# A configuration that weed would refuse fails the start, saying why (ExecStartPre=weed
# check, as weed itself before it is ready)
cp /etc/weed/weed.toml /etc/weed/weed.toml.good
sed -i 's/^\[server\]$/&\nprot = 1/' /etc/weed/weed.toml
check "a configuration that weed would refuse fails systemctl restart" sh -c '! systemctl restart weed'
cp /etc/weed/weed.toml.good /etc/weed/weed.toml
check "...and the journal says why" sh -c "journalctl -u weed -o cat | grep 'unknown option server.prot'"
systemctl reset-failed weed
check "...and once corrected, weed starts" sh -c 'systemctl restart weed && curl -sf 127.0.0.1:9100/healthz'
check "systemctl stop: weed and its workers stop, weed exits 0" t_stop

# --- Socket activation: systemd listens on weed's ports, and passes the sockets
block 'Write /etc/systemd/system/weed.socket' | sed 's/^ListenStream=443$/ListenStream=8080/' >/etc/systemd/system/weed.socket
check "the guide has the socket unit" sh -c "grep -qx 'ListenStream=8080' /etc/systemd/system/weed.socket &&
	grep -qx 'ListenStream=127.0.0.1:9100' /etc/systemd/system/weed.socket"
systemctl daemon-reload
since=$(now)
check "socket activation: the first connection starts weed" t_activated
check "...which serves on the sockets that systemd passed, and binds no port" t_passed "$since"
check "a restart refuses no connection: they wait for weed" t_no_refused
check "systemctl stop weed.socket weed: both stop" sh -c 'systemctl stop weed.socket weed && ! curl -s 127.0.0.1:9100/healthz &&
	[ "$(systemctl show -P ActiveState weed.socket)" = inactive ]'

# --- As an account of its own, with capabilities
useradd -r -M -s /usr/sbin/nologin weed
{
	echo '[Service]'
	block 'Add to \[Service\]:'
} >/etc/systemd/system/weed.service.d/user.conf
check "the guide has the settings for an account of its own" grep -q '^User=weed' /etc/systemd/system/weed.service.d/user.conf
chgrp weed /etc/weed/weed.toml /etc/weed/.htpasswd && chmod 640 /etc/weed/weed.toml /etc/weed/.htpasswd
systemctl daemon-reload
check "as weed: systemctl start returns once weed serves" sh -c 'systemctl start weed && curl -sf 127.0.0.1:9100/healthz'
check "weed runs as weed" t_user weed
check "weed's own process is confined with Landlock" t_confined
check "alice uploads, and the file is hers" t_upload h
check "Delegate=yes: weed runs in main, alice's worker in worker-alice" t_cgroup
check "weed utils ban and unban, as root" t_ban h
check "systemctl stop: weed and its workers stop, weed exits 0" t_stop

echo
echo "$pass passed, $fail failed"
if [ $fail -gt 0 ]; then
	echo "--- journalctl -u weed"
	journalctl -u weed -o cat | tail -40
	exit 1
fi
