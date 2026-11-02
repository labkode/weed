#!/bin/bash
# The lab's load (see run.sh): CLIENTS clients that each pick an account and an
# operation, again and again, and scenes that change what dominates every few minutes
set -u
. /lab/creds.sh
W=https://localhost:9443/webdav
SELF=https://127.0.0.1:9443/webdav # weed itself, as another endpoint of third-party copies
SRC=http://127.0.0.1:8080          # a plain HTTP endpoint that third-party copies pull from
CA=/lab/pki/ca.pem
CLIENTS=${CLIENTS:-16}
NAMES=5 # files f0..f4 of each account
SIZES=(4k 4k 4k 64k 64k 64k 256k 256k 1m 1m 1m 4m 4m 16m 32m)

# Accounts busy all the time, and those that come and go (their workers stop after
# unix_users.idle_timeout)
BUSY=(alice bob carol dave frank atlas001 atlas002 atlas003 atlas004 cms001 cms002 cms003 cms004 cmsprod cmsprod lhcb001 lhcb002)
RARE=(erin atlas005 atlas006 cms005 lhcb003 lhcb004)

C=(curl -s -o /dev/null --cacert $CA --max-time 900)

f() { echo "f$((RANDOM % NAMES))"; }
size() { echo "${SIZES[RANDOM % ${#SIZES[@]}]}"; }

op_get() { "${C[@]}" "${A[@]}" "$W/$u/$(f)"; }
op_put() { "${C[@]}" "${A[@]}" -T /lab/files/$(size) "$W/$u/$(f)"; }
op_head() { "${C[@]}" "${A[@]}" -I "$W/$u/$(f)"; }
op_list() { "${C[@]}" "${A[@]}" -X PROPFIND -H "Depth: 1" "$W/$u/"; }
op_delete() { "${C[@]}" "${A[@]}" -X DELETE "$W/$u/$(f)"; }
# two names: a and b, different
two() { a=$((RANDOM % NAMES)) b=$(((a + 1 + RANDOM % (NAMES - 1)) % NAMES)); }
op_move() { two; "${C[@]}" "${A[@]}" -X MOVE -H "Destination: $W/$u/f$b" "$W/$u/f$a"; }
op_copy() { two; "${C[@]}" "${A[@]}" -X COPY -H "Destination: $W/$u/f$b" "$W/$u/f$a"; }
op_dir() {
	"${C[@]}" "${A[@]}" -X MKCOL "$W/$u/d/"
	"${C[@]}" "${A[@]}" -T /lab/files/4k "$W/$u/d/x"
	"${C[@]}" "${A[@]}" -X DELETE "$W/$u/d/"
}
# Third-party copies: pulls from the HTTP endpoint, and with credentials to pass on,
# pulls from weed itself and pushes to it
op_pull() { "${C[@]}" "${A[@]}" -X COPY -H "Source: $SRC/$(size)" "$W/$u/$(f)"; }
op_tpc() {
	[ -z "$T" ] && { op_pull; return; }
	if ((RANDOM % 2)); then
		"${C[@]}" "${A[@]}" -X COPY -H "Source: $SELF/$u/$(f)" -H "TransferHeaderAuthorization: $T" "$W/$u/$(f)"
	else
		"${C[@]}" "${A[@]}" -X COPY -H "Destination: $SELF/$u/$(f)" -H "TransferHeaderAuthorization: $T" "$W/$u/$(f)"
	fi
}
# A macaroon, minted with the account's credentials, then used alone (weed mints none
# for a token)
op_macaroon() {
	local m
	[ ${KIND[$u]} = token ] && { op_get; return; }
	m=$(curl -s --cacert $CA "${A[@]}" -X POST -H "Content-Type: application/macaroon-request" \
		-d '{"caveats": ["activity:DOWNLOAD,LIST"], "validity": "PT10M"}' "$W/$u/" | jq -r .macaroon 2>/dev/null)
	[ -n "$m" ] && [ "$m" != null ] && "${C[@]}" -H "Authorization: Bearer $m" "$W/$u/$(f)"
}
# What weed refuses: a wrong password, a certificate the grid-mapfile does not list,
# an expired token, a file in a directory the account cannot write
op_bad() {
	case $((RANDOM % 4)) in
	0) "${C[@]}" -u "dave:wrong" "$W/dave/f0" ;;
	1) "${C[@]}" --cert /lab/pki/mallory.pem --key /lab/pki/mallory.key "$W/alice/" ;;
	2) "${C[@]}" -H "Authorization: Bearer $(</lab/tokens/expired)" "$W/atlas001/f0" ;;
	3) "${C[@]}" "${A[@]}" -T /lab/files/4k "$W/intruder-$u" ;;
	esac
}
OPS=(get get get get get get get put put put put put head head list list list delete move copy dir pull tpc tpc macaroon bad)

client() {
	while :; do
		if ((RANDOM % 100 < 4)); then auth_of ${RARE[RANDOM % ${#RARE[@]}]}; else auth_of ${BUSY[RANDOM % ${#BUSY[@]}]}; fi
		op_${OPS[RANDOM % ${#OPS[@]}]} >/dev/null 2>&1
		sleep 0.$((RANDOM % 10))
	done
}

# repeat seconds parallel account op...: runs the ops of account in parallel loops
repeat() {
	local end=$((EPOCHSECONDS + $1)) n=$2 who=$3
	shift 3
	local ops=("$@")
	for i in $(seq $n); do
		(
			auth_of $who
			while ((EPOCHSECONDS < end)); do op_${ops[RANDOM % ${#ops[@]}]} >/dev/null 2>&1; done
		) &
	done
}
op_big_get() { "${C[@]}" "${A[@]}" "$W/$u/big"; }
op_big_put() { "${C[@]}" "${A[@]}" -T /lab/files/32m "$W/$u/big"; }
op_mid_get() { "${C[@]}" "${A[@]}" "$W/$u/mid"; }
op_pull_big() { "${C[@]}" "${A[@]}" -X COPY -H "Source: $SRC/32m" "$W/$u/big"; }
say() { echo "$(date +%T) $*"; }

scenes() {
	# The files the scenes download
	for u in cmsprod cms001 atlas001 alice lhcb001; do
		auth_of $u
		op_big_put
	done
	auth_of frank
	"${C[@]}" "${A[@]}" -T /lab/files/16m "$W/frank/mid"
	while :; do
		say "scene downloads: cmsprod, cms001 and atlas001 (cpu.weight 300 and 200), alice and lhcb001 download 32 MiB files, 2 at a time each"
		for u in cmsprod cms001 atlas001 alice lhcb001; do repeat 150 2 $u big_get; done
		wait_scene 150
		say "scene uploads: cms002, atlas002, dave, alice and lhcb002 upload 32 MiB files, 2 at a time each"
		for u in cms002 atlas002 dave alice lhcb002; do repeat 150 2 $u big_put; done
		wait_scene 150
		say "scene many: frank downloads 16 MiB files 60 at a time, his workers in 384M of memory"
		repeat 120 60 frank mid_get
		wait_scene 120
		say "scene tpc: third-party copies of 32 MiB, pulled over plain HTTP by atlas003, cms003, carol and lhcb003, 3 at a time each"
		for u in atlas003 cms003 carol lhcb003; do repeat 120 3 $u pull_big; done
		wait_scene 120
		say "scene quiet: only the $CLIENTS clients"
		sleep 120
	done
}
wait_scene() { sleep $1; wait_children; }
# The clients run for ever: wait for the scene's loops only
wait_children() {
	local p
	for p in $(jobs -p); do
		[[ " $CLIENT_PIDS " == *" $p "* ]] || wait $p
	done
}

# Every account starts with its files
for u in "${!KIND[@]}"; do
	(
		auth_of $u
		for n in $(seq 0 $((NAMES - 1))); do "${C[@]}" "${A[@]}" -T /lab/files/$(size) "$W/$u/f$n"; done
	) &
done
wait
say "the files of ${#KIND[@]} accounts are uploaded"

CLIENT_PIDS=""
for i in $(seq $CLIENTS); do
	client &
	CLIENT_PIDS+=" $!"
done
say "$CLIENTS clients started"
scenes
