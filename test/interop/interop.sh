#!/bin/sh
# Interoperability tests: runs weed against real WLCG clients (gfal2, davix) and a
# reference HTTP-TPC implementation (XRootD) in a Podman container, with X.509
# proxies, macaroons and WLCG tokens. Needs Go, and Podman, which it runs as root
# (sudo).
#
#     test/interop/interop.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
podman() { if [ "$(id -u)" = 0 ]; then command podman "$@"; else sudo podman "$@"; fi; }

build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
(cd "$root" && CGO_ENABLED=0 go build -o "$build/weed" . &&
	CGO_ENABLED=0 go build -o "$build/issuer" ./test/interop/issuer)
cp "$here/run.sh" "$build/"

podman build -q -t weed-interop "$here" >/dev/null
# Copied into the container, not mounted, which SELinux would need labels for
tar -C "$build" -cf - weed issuer run.sh | podman run --rm -i weed-interop bash -c \
	'mkdir /build && tar -x -C /build && install /build/weed /build/issuer /usr/local/bin/ && exec bash /build/run.sh </dev/null'
