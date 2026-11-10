#!/bin/bash
# Interoperability with other WLCG storage systems: weed and each system copy files to
# each other, with both of them pulling and pushing, driven by gfal2 with an X.509
# proxy (storage/run.sh). A system runs from storage/<name>/: its Containerfile, the
# start.sh that it runs with the test certificates in /pki, test.env, which says where
# the test writes in it, and version.sh, which prints its version in its image. Its
# containers, the test container (weed-interop) and weed share a Podman pod, so that
# all of them are on localhost, and on its hostname. The systems run one after the
# other, and a table of their versions and results ends the output. Needs Go, and
# Podman, which it runs as root (sudo), or as yourself with ROOTLESS=1.
#
#     test/interop/storage.sh               # every system
#     test/interop/storage.sh dcache eos    # these
#
# storage/<name>/pod.sh, if there is one, defines before_storage, which starts what the
# system needs besides its own container, such as a database, with $pod set.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
podman() { if [ "$(id -u)" = 0 ] || [ "${ROOTLESS:-}" = 1 ]; then command podman "$@"; else sudo podman "$@"; fi; }

# table results [md]: the results, a row per system (name, version, result, passed,
# failed, seconds, failed checks, weed's version, gfal2's), as a table, or with md as
# Markdown; then the failed checks, and what tested them
table() {
	awk -F'\t' -v md="${2:-}" '
	{
		n++
		for (i = 1; i <= 7; i++) c[n, i] = $i
		c[n, 6] = $6 == "-" ? "-" : $6 " s"
		if ($8 != "") weed = $8
		if ($9 != "") gfal2 = $9
	}
	END {
		split("system version result passed failed time", h, " ")
		for (i = 1; i <= 6; i++) w[i] = length(h[i])
		for (r = 1; r <= n; r++) for (i = 1; i <= 6; i++) if (length(c[r, i]) > w[i]) w[i] = length(c[r, i])
		if (md) {
			print "| system | version | result | passed | failed | time |"
			print "|---|---|---|--:|--:|--:|"
			for (r = 1; r <= n; r++)
				printf "| %s | %s | %s | %s | %s | %s |\n", c[r, 1], c[r, 2], c[r, 3], c[r, 4], c[r, 5], c[r, 6]
		} else {
			f = "%-" w[1] "s  %-" w[2] "s  %-" w[3] "s  %" w[4] "s  %" w[5] "s  %" w[6] "s\n"
			printf f, h[1], h[2], h[3], h[4], h[5], h[6]
			for (r = 1; r <= n; r++) printf f, c[r, 1], c[r, 2], c[r, 3], c[r, 4], c[r, 5], c[r, 6]
		}
		for (r = 1; r <= n; r++) {
			if (c[r, 7] == "") continue
			if (!failed++) print "\nFailed:\n"
			k = split(c[r, 7], fs, "; ")
			for (j = 1; j <= k; j++) printf "%s%s: %s\n", (md ? "- " : "  "), c[r, 1], fs[j]
		}
		if (weed != "") printf "\nTested with weed %s and gfal2 %s.\n", weed, gfal2
	}' "$1"
}

# Every system, or those named, each in its own run of this script, then the table
if [ -z "${STORAGE_RESULTS:-}" ]; then
	all=$(cd "$here/storage" && for d in */; do [ -f "$d/Containerfile" ] && echo "${d%/}"; done)
	# shellcheck disable=SC2086
	[ $# -gt 0 ] || set -- $all
	for name in "$@"; do
		[ -f "$here/storage/$name/Containerfile" ] || { echo "no storage $name; there are:" $all >&2; exit 2; }
	done
	results=$(mktemp)
	trap 'rm -f "$results"' EXIT
	for name in "$@"; do
		echo "=== $name"
		STORAGE_RESULTS=$results "$here/storage.sh" "$name" || true
		# One that stopped before it could say
		grep -q "^$name"$'\t' "$results" ||
			printf '%s\t?\tnot ok\t-\t-\t-\tno result: see its output\t\t\n' "$name" >>"$results"
	done
	echo
	table "$results"
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		table "$results" md >>"$GITHUB_STEP_SUMMARY"
	fi
	if grep -q $'\tnot ok\t' "$results"; then
		exit 1
	fi
	exit 0
fi

name=$1
dir=$here/storage/$name

# annotate: stdin as an error annotation of the GitHub Actions job, which the job's
# summary and the pull request show without the log
annotate() {
	[ -n "${GITHUB_ACTIONS:-}" ] || { cat >/dev/null; return; }
	cut -c1-400 | awk '{ m = m (NR > 1 ? "\n" : "") $0 }
		END { gsub(/%/, "%25", m); gsub(/\r/, "%0D", m); gsub(/\n/, "%0A", m); print "::error::" m }'
}

pod=weed-$name-$$
build=$(mktemp -d)
status=1
version=? weed= gfal2=
cleanup() {
	if [ $status != 0 ]; then
		for c in $(podman ps -a --pod --filter pod=$pod --format '{{.Names}}' | grep -v infra); do
			echo "--- tail of the logs of $c"
			podman logs --tail 60 $c 2>&1
		done
		# Each failed check with its output, and the end of the system's log
		[ -f "$build/out" ] && awk '/^FAIL  / { n++ } /^FAIL  |^      \|/ { print > (dir "/fail." n) }' \
			dir="$build" "$build/out"
		for f in "$build"/fail.*; do
			[ -f "$f" ] && annotate <"$f"
		done
		{ echo "the end of the log of $name"; podman logs --tail 25 $pod-$name 2>&1; } | annotate
	fi
	# The row of the table
	local result=ok counts fails
	[ $status = 0 ] || result="not ok"
	counts=$(sed -n 's/^\([0-9]*\) passed, \([0-9]*\) failed$/\1\t\2/p' "$build/out" 2>/dev/null | tail -1)
	[ -n "$counts" ] || counts=$'-\t-'
	fails=$(sed -n 's/^FAIL  //p' "$build/out" 2>/dev/null | awk '{ printf "%s%s", (NR > 1 ? "; " : ""), $0 }')
	[ $status = 0 ] || [ -n "$fails" ] || fails="stopped before its checks: see its output"
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$version" "$result" "$counts" $SECONDS "$fails" "$weed" "$gfal2" \
		>>"$STORAGE_RESULTS"
	podman pod rm -f $pod >/dev/null 2>&1 || true
	podman volume rm -f $pod-pki >/dev/null 2>&1 || true
	rm -rf "$build"
}
trap cleanup EXIT

(cd "$root" && CGO_ENABLED=0 go build -o "$build/weed" .)
weed=$("$build/weed" version | sed -n '1s/^weed //p')
cp "$here/lib.sh" "$here/storage/run.sh" "$build/"
podman build -q -t weed-interop "$here" >/dev/null
gfal2=$(podman run --rm weed-interop rpm -q --qf '%{VERSION}' gfal2 2>/dev/null || true)
podman build -q -t weed-storage-$name "$dir" >/dev/null
if [ -f "$dir/version.sh" ]; then
	version=$(podman run --rm -i --entrypoint sh weed-storage-$name -s <"$dir/version.sh" 2>/dev/null | head -1)
	version=${version:-?}
fi

before_storage() { :; }
[ -f "$dir/pod.sh" ] && . "$dir/pod.sh"
# On Podman's bridge network, as with root by default: the pod's hostname is then on a
# private address, as in CI, however Podman runs
podman pod create --name $pod --hostname storage.interop.test --network bridge >/dev/null
podman volume create $pod-pki >/dev/null
# The certificates, for everyone, made in the pod for its address (make_pki)
tar -C "$build" -cf - lib.sh | podman run --rm -i --pod $pod -v $pod-pki:/pki weed-interop bash -c \
	'mkdir /build && tar -x -C /build && cd /pki && . /build/lib.sh && make_pki && echo "$USER_DN" >user.dn && chmod -R a+r /pki'

before_storage
podman run -d -q --pod $pod --name $pod-$name -v $pod-pki:/pki:ro weed-storage-$name >/dev/null

# Copied into the container, not mounted, which SELinux would need labels for
set +e
tar -C "$build" -cf - weed lib.sh run.sh | podman run --rm -i --pod $pod -v $pod-pki:/pki:ro \
	--env-file "$dir/test.env" -e STORAGE=$name weed-interop bash -c \
	'mkdir /build && tar -x -C /build && install /build/weed /usr/local/bin/ && exec bash /build/run.sh </dev/null' |
	tee "$build/out"
status=${PIPESTATUS[1]}
exit $status
