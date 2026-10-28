#!/bin/sh
# Interoperability tests: runs weed against real WLCG clients (gfal2, davix) and a
# reference HTTP-TPC implementation (XRootD) in a container. Needs Go and Docker.
#
#     test/interop/interop.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

case $(docker info --format '{{.Architecture}}') in
	x86_64 | amd64) goarch=amd64 ;;
	aarch64 | arm64) goarch=arm64 ;;
	*) echo "unsupported docker architecture" >&2; exit 1 ;;
esac
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
(cd "$root" && GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o "$build/weed" .)

docker build -q -t weed-interop "$here" >/dev/null
docker run --rm \
	-v "$build/weed:/usr/local/bin/weed:ro" \
	-v "$here/run.sh:/run.sh:ro" \
	weed-interop bash /run.sh
