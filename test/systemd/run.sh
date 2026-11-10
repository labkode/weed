#!/bin/bash
# Runs inside the weed-systemd container (see systemd.sh), whose PID 1 is systemd: weed
# installed from its RPM (/test/weed.rpm) as the guide says (/test/installation.md,
# from docs/src), its unit, which runs weed as the account weed, with the sandboxing
# that the guide suggests; then as root
set -uo pipefail
# With pipefail, cmd | grep -q fails when grep's early exit kills cmd (SIGPIPE): grep
# a here-string (<<<"$(cmd)") instead

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

# --- The RPM, whose unit is the guide's
rpm -i /test/weed.rpm
check "the RPM makes the account weed, its group, and /etc/weed for it" sh -c 'id weed && [ "$(stat -c %U:%G:%a /etc/weed)" = root:weed:750 ] &&
	[ "$(stat -c %U:%G:%a /etc/weed/weed.toml)" = root:weed:640 ] && [ "$(stat -c %G:%a /etc/weed/.htpasswd)" = weed:640 ]'
block 'Write /etc/systemd/system/weed.service' | sed 's#/usr/local/bin/weed#/usr/bin/weed#g' >/tmp/guide.service
check "the RPM's unit is the guide's" diff -B /tmp/guide.service /usr/lib/systemd/system/weed.service
check "...and its sysctl settings, the guide's" sh -c "grep -qx 'net.core.wmem_max = 1048576' /usr/lib/sysctl.d/60-weed.conf"
check "...and a logrotate file for server.log_file" logrotate -d /etc/logrotate.d/weed
systemctl daemon-reload
check "the RPM's configuration: weed starts, serves /srv/weed to this machine, asking for a password" sh -c '
	systemctl start weed && curl -sf 127.0.0.1:9180/healthz &&
	[ "$(curl -s -o /dev/null -w %{http_code} -X PROPFIND http://127.0.0.1:8080/webdav/)" = 401 ] &&
	journalctl -u weed -o cat | grep -q "dir=/srv/weed" && systemctl stop weed'
mkdir -p /etc/systemd/system/weed.service.d
{
	echo '[Service]'
	block 'For instance, in \[Service\]:'
} >/etc/systemd/system/weed.service.d/sandbox.conf
check "the guide has the sandboxing" sh -c "grep -q '^ProtectSystem=strict' /etc/systemd/system/weed.service.d/sandbox.conf"

# --- Two accounts, which log in with passwords; bob not yet
useradd -M -u 6001 alice
useradd -M -u 6002 bob
mkdir -p /data/alice /data/bob && chown alice: /data/alice && chown bob: /data/bob
# In the RPM's .htpasswd (basic.htpasswd of /etc/weed/weed.toml), which weed's group may read
check "weed utils password, from stdin, sets alice's in the RPM's .htpasswd, which stays root:weed 0640" sh -c "
	printf 'pw-alice\n' | weed utils password alice | grep -q 'Added alice to /etc/weed/.htpasswd' &&
	grep -q '^alice:' /etc/weed/.htpasswd && [ \"\$(stat -c %U:%G:%a /etc/weed/.htpasswd)\" = root:weed:640 ]"
cat >/etc/weed/weed.toml <<'T'
[server]
port = 8080
dir = "/data"
metrics_address = "127.0.0.1:9180"

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
starter() { pgrep -P "$(main)" | head -1; } # weed's only child; its workers are the starter's
t_cgroup() { # weed and its starter in <its cgroup>/main, alice's worker in worker-alice
	local w
	grep -qx "$(main)" $CG/main/cgroup.procs && grep -qx "$(starter)" $CG/main/cgroup.procs &&
		w=$(head -1 $CG/worker-alice/cgroup.procs) && [ -n "$w" ] && [ "$(ps -o user= -p "$w")" = alice ]
}
caps() { awk -v k="$2:" '$1 == k { print $2 }' /proc/"$1"/status; }
t_caps() { # weed has no capabilities; the starter of its workers, those to start and kill them
	local s
	s=$(starter) && [ "$(tr '\0' ' ' </proc/"$s"/cmdline)" = "weed starter -config /etc/weed/weed.toml " ] &&
		[ "$(caps "$(main)" CapPrm)" = 0000000000000000 ] && [ "$(caps "$(main)" CapEff)" = 0000000000000000 ] &&
		[ "$(caps "$s" CapPrm)" = 00000000000000e0 ] && [ "$(caps "$s" CapEff)" = 00000000000000e0 ] &&
		[ "$(ps -o user= -p "$s")" = "$1" ] && [ "$(caps "$s" NoNewPrivs)" = 1 ] ||
		{ grep -E '^(Uid|Cap|NoNew)' /proc/"$(main)"/status /proc/"$s"/status; return 1; }
}
t_ban() { # through admin.socket, in RuntimeDirectory; the bans in StateDirectory; alice's file $1
	weed utils ban -reason test alice && ! as alice -o /dev/null $W/alice/$1 &&
		grep -q alice /var/lib/weed/bans.json &&
		weed utils unban alice && as alice -o /dev/null $W/alice/$1
}
t_ban_kills() { # a ban kills alice's workers, the one of her upload in progress too
	local up out ok=1
	# 1 byte a second: the upload lasts minutes, unless its worker is killed
	curl -sS -u alice:pw-alice --limit-rate 1 -T /etc/os-release -o /dev/null $W/alice/slow 2>/dev/null &
	up=$!
	for i in $(seq 40); do
		pgrep -u alice >/dev/null && break
		sleep 0.25
	done
	out=$(timeout 30 weed utils ban -reason test alice 2>&1) && grep -q 'stopped its [0-9]* worker process' <<<"$out" &&
		for i in $(seq 20); do # the starter reaps them
			pgrep -u alice >/dev/null || { ok=0; break; }
			sleep 0.25
		done
	echo "$out"
	ps -o pid,user,stat,args -u alice
	weed utils unban alice
	kill $up 2>/dev/null
	wait $up 2>/dev/null
	return $ok
}
t_limits() { # weed limits, as alice, while weed serves: a weed of its own in a scope, and nothing left behind
	weed limits -quick -account alice -out /tmp/limits -- -scenarios get-small,put-small >/tmp/limits.out 2>&1 ||
		{ tail -20 /tmp/limits.out; return 1; }
	grep '^  get-small ' /tmp/limits/summary.txt && grep 'weed and its workers used at most' /tmp/limits/summary.txt &&
		! grep TasksMax /tmp/limits/summary.txt && [ -z "$(ls -A /data /var/tmp | grep weed-limits)" ] &&
		! systemctl list-units --all 'weed-limits-*' | grep weed-limits &&
		{ [ ! -e /tmp/limits/weed.toml ] || weed check -as root -config /tmp/limits/weed.toml; } && curl -sf 127.0.0.1:9180/healthz
}
t_readonly() { ! nsenter -t "$(main)" -m touch /etc/weed/probe; }
t_writable() {
	nsenter -t "$(main)" -m sh -c 'touch /data/probe /run/weed/probe /var/lib/weed/probe /var/log/weed/probe &&
		rm /data/probe /run/weed/probe /var/lib/weed/probe /var/log/weed/probe'
}
t_home() { [ -n "$(ls -A /root)" ] && [ -z "$(nsenter -t "$(main)" -m ls -A /root)" ]; }
t_tpc() { # the worker connects to weed, as to another server
	as alice -X COPY -H "Source: $W/alice/f" -H "TransferHeaderAuthorization: Basic $(printf alice:pw-alice | base64)" \
		$W/alice/g | tail -1 | grep '^success' && cmp /data/alice/f /data/alice/g
}
t_refused() { ! as bob -T /etc/os-release $W/bob/f; }
t_check_as() { # weed check, as root, of a file that root may read, and weed not
	local out
	chmod 600 /etc/weed/.htpasswd
	out=$(weed check -config /etc/weed/weed.toml 2>&1)
	chmod 640 /etc/weed/.htpasswd
	grep -q 'not as the account weed that it runs as (User= of weed.service)' <<<"$out" &&
		grep -q '/etc/weed/.htpasswd: permission denied' <<<"$out" || { echo "$out"; return 1; }
}
t_hardened() { # with systemd's directive $1, weed does not start, and says which
	mkdir -p /etc/systemd/system/weed.service.d
	printf '[Service]\n%s=yes\n' "$1" >/etc/systemd/system/weed.service.d/hardening.conf
	systemctl daemon-reload
	! systemctl restart weed
	local refused=$?
	rm /etc/systemd/system/weed.service.d/hardening.conf
	systemctl daemon-reload
	systemctl reset-failed weed
	[ $refused = 0 ] && grep -q "systemd's $1= does" <<<"$(journalctl -u weed -o cat)" ||
		{ journalctl -u weed -o cat | tail -5; return 1; }
}
t_upgrade() { # rpm -U of a weed: it checks the configuration, and says that weed runs on; $1 is what it says
	local out
	out=$(rpm -U --replacepkgs /test/weed.rpm 2>&1)
	grep -q "$1" <<<"$out" || { echo "$out"; return 1; }
}
t_logrotate() { # server.log_file: logrotate moves it, and weed writes a new one
	sed -i 's|^metrics_address = .*|&\nlog_file = "/var/log/weed/weed.log"|' /etc/weed/weed.toml
	systemctl restart weed && as alice -o /dev/null -T /etc/os-release $W/alice/rot1 &&
		grep -q 'msg=request' /var/log/weed/weed.log &&
		logrotate -f /etc/logrotate.d/weed && as alice -o /dev/null -T /etc/os-release $W/alice/rot2 &&
		grep -q 'msg=request' /var/log/weed/weed.log.1 && grep -q 'msg=request' /var/log/weed/weed.log
	local ok=$?
	sed -i '/^log_file = /d' /etc/weed/weed.toml
	systemctl restart weed
	return $ok
}
t_reload() {
	printf 'pw-bob\n' | weed utils password bob >/dev/null && systemctl reload weed &&
		as bob -T /etc/os-release $W/bob/f
}
serving() { # a weed other than $1 serves: within 90 s, as systemd restarts it ever less often
	local p
	for i in $(seq 180); do
		p=$(main)
		[ "$p" != 0 ] && [ "$p" != "$1" ] && curl -sf 127.0.0.1:9180/healthz >/dev/null && return 0
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
t_remounted() { # weed $1 replaced alice's worker after $2, confined to the storage now mounted, and goes on
	for i in $(seq 40); do
		logged "$2" 'the exported directory has changed since the worker started' && break
		sleep 0.5
	done
	logged "$2" 'the exported directory has changed since the worker started' && [ "$(main)" = "$1" ] ||
		{ journalctl -u weed -o cat --since "$2" | grep -E 'exit|status=|directory|confine workers|Stopp|Starting|Main process' | cut -c1-300; return 1; }
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
		[ "$(curl -s -o /dev/null -w '%{http_code}' 127.0.0.1:9180/healthz)" = 503 ] &&
		logged "$2" 'the storage of the exported directory is no longer mounted' &&
		systemctl show -P StatusText weed | grep '^Blocked since .*, the storage of /data not mounted' &&
		curl -s 127.0.0.1:9180/metrics | grep -x 'weed_storage_unmounted 1' &&
		curl -s 127.0.0.1:9180/status | jq -e .storage_unmounted || return 1
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
		! curl -sf 127.0.0.1:9180/healthz
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
		[ "$(main)" = "$pid" ] && [ "$(systemctl show -P ActiveState weed)" = active ] && curl -sf 127.0.0.1:9180/healthz ||
		{ echo "worker $w, weed $pid now $(main)"; grep oom $CG/memory.events; ps -o pid,user,rss,args -u alice; return 1; }
}
t_oom_next() { # the account's next request gets a worker again
	[ -f $CG/worker-alice/memory.max ] && echo max >$CG/worker-alice/memory.max
	t_serves oom
}
t_activated() { # the first connection to weed.socket starts weed
	systemctl start weed.socket && [ "$(systemctl show -P ActiveState weed)" = inactive ] &&
		curl -sf --max-time 60 127.0.0.1:9180/healthz && [ "$(systemctl show -P ActiveState weed)" = active ]
}
t_passed() { # weed took the sockets of systemd, and binds no port
	logged "$1" 'msg=listening address=.*:8080 scheme=http socket="passed by systemd"' &&
		logged "$1" 'msg="serving metrics" address=127.0.0.1:9180 socket="passed by systemd"' &&
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
t_stop() { # weed, its starter and its workers stop, and weed exits 0
	systemctl stop weed && [ "$(systemctl show -P Result weed)" = success ] &&
		[ "$(systemctl show -P ExecMainStatus weed)" = 0 ] && ! pgrep -u alice && ! pgrep -f 'weed starter'
}

# --- As weed, the RPM's unit
# Mounts made here reach weed's namespace (ProtectSystem=), as on a host, where systemd
# makes / shared; a container's is private
mount --make-rshared /
systemctl daemon-reload
check "weed check accepts the configuration" weed check -config /etc/weed/weed.toml
check "...as root, and as the account weed, which the unit runs weed as" sh -c "
	weed check -config /etc/weed/weed.toml | grep -q 'as the account weed too (User= of weed.service)'"
check "...and as root, it says which file the account weed may not read" t_check_as
# Type=notify: systemctl returns once weed says it is ready, and it serves then
check "systemctl start returns once weed serves" sh -c 'systemctl start weed && curl -sf 127.0.0.1:9180/healthz'
check "the status line says since when weed serves" sh -c "systemctl show -P StatusText weed | grep '^Serving since'"
check "TasksMax=infinity: systemd does not bound weed's threads" sh -c '[ "$(systemctl show -P TasksMax weed)" = infinity ]'
check "weed's log is in the journal, its starter's too: workers confined with Landlock" sh -c "journalctl -u weed -o cat | grep 'workers are confined with Landlock.*process=starter'"
check "weed runs as weed" t_user weed
check "weed's own process is confined with Landlock" t_confined
check "weed has no capabilities; its starter, as weed, CAP_SETUID, CAP_SETGID and CAP_KILL alone" t_caps weed
check "alice uploads, and the file is hers" t_upload f
check "a GET gives it back" t_get
check "Delegate=yes: weed and its starter run in main, alice's worker in worker-alice" t_cgroup
check "ProtectSystem=strict: weed may not write /etc" t_readonly
check "...but /data, /run/weed, /var/lib/weed and /var/log/weed (LogsDirectory=, for server.log_file)" t_writable
check "ProtectHome=yes: /root is empty to weed" t_home
check "a third-party copy that weed pulls from itself" t_tpc
check "bob, without a password, is refused" t_refused
check "systemctl reload re-reads the passwords: bob's, added, works" t_reload
check "weed utils ban and unban" t_ban f
check "a ban kills the user's worker at once, aborting the upload in progress" t_ban_kills
check "weed limits measures a weed of its own, suggests no TasksMax for the guide's unit, and leaves nothing" t_limits
# A storage mounted over the exported directory, as for a remount: workers confined to
# the directory as it was are replaced by workers confined to the storage
as alice -o /dev/null $W/alice/f # a worker of alice's, ready
old=$(main) since=$(now)
storage
check "a storage mounted over the exported directory: the same weed replaces the workers" t_remounted "$old" "$since"
check "...which serve that storage" t_serves n
# Unmounted: weed blocks, never serving the directory beneath, until it is mounted again
old=$(main) since=$(now)
umount /data
check "its storage unmounted, weed blocks: 503, /healthz too, the same weed goes on" t_blocked "$old" "$since"
check "...nor does anything land in the directory beneath" t_beneath
storage
check "...mounted again: the same weed serves it" sh -c "[ \"\$(systemctl show -P MainPID weed)\" = $old ]"
check "...and its upload lands there" t_serves m
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
check "...and once corrected, weed starts" sh -c 'systemctl restart weed && curl -sf 127.0.0.1:9180/healthz'
check "RestrictSUIDSGID= in a drop-in: weed does not start, and says why" t_hardened RestrictSUIDSGID
check "RestrictNamespaces= in a drop-in: weed does not start, and says why" t_hardened RestrictNamespaces
check "...and without, weed starts" sh -c 'systemctl restart weed && curl -sf 127.0.0.1:9180/healthz'
check "an upgrade checks the configuration with the new weed, which the running one goes on until restarted" \
	t_upgrade 'the running weed is the version before, until systemctl restart weed'
sed -i 's/^\[server\]$/&\nprot = 1/' /etc/weed/weed.toml
check "...and warns of one that the new weed would refuse" t_upgrade 'would not start with /etc/weed/weed.toml'
cp /etc/weed/weed.toml.good /etc/weed/weed.toml
cp /usr/lib/systemd/system/weed.service /etc/systemd/system/weed.service # the same: weed runs on
check "...and of a unit in /etc/systemd/system that hides the RPM's" t_upgrade '/etc/systemd/system/weed.service hides the unit of this RPM'
rm /etc/systemd/system/weed.service
systemctl daemon-reload
check "server.log_file: logrotate, with the RPM's file, rotates it, and weed writes a new one" t_logrotate
check "systemctl stop: weed, its starter and its workers stop, weed exits 0" t_stop

# --- Socket activation: systemd listens on weed's ports, and passes the sockets
block 'Write /etc/systemd/system/weed.socket' | sed 's/^ListenStream=443$/ListenStream=8080/' >/etc/systemd/system/weed.socket
check "the guide has the socket unit" sh -c "grep -qx 'ListenStream=8080' /etc/systemd/system/weed.socket &&
	grep -qx 'ListenStream=127.0.0.1:9180' /etc/systemd/system/weed.socket"
systemctl daemon-reload
since=$(now)
check "socket activation: the first connection starts weed" t_activated
check "...which serves on the sockets that systemd passed, and binds no port" t_passed "$since"
check "a restart refuses no connection: they wait for weed" t_no_refused
check "systemctl stop weed.socket weed: both stop" sh -c 'systemctl stop weed.socket weed && ! curl -s 127.0.0.1:9180/healthz &&
	[ "$(systemctl show -P ActiveState weed.socket)" = inactive ]'

# --- As root, as the guide's drop-in has it
block 'run it as root, with a drop-in' >/etc/systemd/system/weed.service.d/root.conf
check "the guide has the drop-in for root" grep -qx 'User=root' /etc/systemd/system/weed.service.d/root.conf
systemctl daemon-reload
check "as root: systemctl start returns once weed serves" sh -c 'systemctl start weed && curl -sf 127.0.0.1:9180/healthz'
check "weed runs as root" t_user root
check "...without capabilities; its starter, as root, CAP_SETUID, CAP_SETGID and CAP_KILL alone" t_caps root
check "alice uploads, and the file is hers" t_upload r
check "a ban kills the user's worker at once, aborting the upload in progress" t_ban_kills
check "systemctl stop: weed, its starter and its workers stop, weed exits 0" t_stop

echo
echo "$pass passed, $fail failed"
if [ $fail -gt 0 ]; then
	echo "--- journalctl -u weed"
	journalctl -u weed -o cat | tail -40
	exit 1
fi
