#!/bin/sh
# make find-limits-users: the limits of weed serving many accounts to crowds of
# thousands of clients, in a privileged Podman container on this machine: USERS
# accounts (100) that authenticate with WLCG tokens, each with a worker of its own in
# a cgroup of its own, weed's files on a volume, and test/stress beside weed. It grows
# get-small over more and more accounts (accounts), then crowds of up to 8192 clients
# spread over the accounts, that each hold a connection and make a request every
# second (clients) or download slowly, as jobs across a WAN (slow-download; a file of
# 64 MiB per account). The arguments go to stress (stress -h), e.g. -clients 16384;
# the results are in test/limits/out. weed's dashboard is on
# http://127.0.0.1:9100/dashboard/ (METRICS_PORT) while it runs. Needs Go, and
# Podman, which it runs as root (sudo).
#
#     [USERS=n] test/limits/users.sh [stress arguments]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
podman() { if [ "$(id -u)" = 0 ]; then command podman "$@"; else sudo podman "$@"; fi; }
users=${USERS:-100}
metrics=${METRICS_PORT:-9100}
name=weed-find-limits-users
out=$here/out

build=$(mktemp -d)
results=
finish() {
	if podman inspect $name >/dev/null 2>&1; then
		# stress, if it still runs, stops and reports what it measured
		podman stop -t 120 $name >/dev/null 2>&1 || true
		mkdir -p "$out"
		for f in txt json; do
			podman cp $name:/limits/limits.$f - 2>/dev/null | tar -xOf - >"$build/limits.$f" 2>/dev/null || true
			if [ -s "$build/limits.$f" ]; then mv "$build/limits.$f" "$out/find-limits-users.$f" && results=1; fi
		done
		podman rm -f -v $name >/dev/null 2>&1 || true
	fi
	rm -rf "$build"
}
trap finish EXIT
trap 'exit 130' INT TERM
echo "find-limits-users: building weed, test/stress and a token issuer"
(cd "$root" && CGO_ENABLED=0 go build -o "$build/weed" . && CGO_ENABLED=0 go build -o "$build/stress" ./test/stress &&
	CGO_ENABLED=0 go build -o "$build/issuer" ./test/interop/issuer)

podman build -q -t weed-find-limits "$here" >/dev/null
podman rm -f -v $name >/dev/null 2>&1 || true
# A terminal, for Ctrl-C to reach stress
tty=
if [ -t 0 ] && [ -t 1 ]; then tty=-t; fi
# weed's files on a volume of its own, which removing the container removes
podman create $tty --name $name --privileged -v /data -e USERS="$users" -e METRICS_PORT="$metrics" \
	-p 127.0.0.1:"$metrics":9100 weed-find-limits bash /limits/run.sh \
	-scenarios accounts,clients,slow-download -crowd-accounts -download-size 64MiB "$@" >/dev/null
# Copied into the container, not mounted, which SELinux would need labels for
for b in weed stress issuer; do podman cp "$build/$b" $name:/usr/local/bin/$b; done
podman cp "$here/users-run.sh" $name:/limits/run.sh
echo "find-limits-users: weed starts, with $users accounts"
podman start -a ${tty:+-i} $name || true
status=$(podman inspect -f '{{.State.ExitCode}}' $name)
finish
trap - EXIT
echo
if [ -n "$results" ]; then
	echo "find-limits-users: the results are in ${out#"$root"/}/find-limits-users.txt and find-limits-users.json"
fi
exit "$status"
