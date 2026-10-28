#!/bin/sh
# Interoperability tests: runs weed against real WLCG clients (gfal2, davix) and a
# reference HTTP-TPC implementation (XRootD) in a container, with X.509 proxies,
# macaroons and WLCG tokens. Needs Go and Docker.
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
(cd "$root" && GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o "$build/weed" . &&
	GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o "$build/issuer" ./test/interop/issuer)

docker build -q -t weed-interop "$here" >/dev/null
docker run --rm \
	-v "$build/weed:/usr/local/bin/weed:ro" \
	-v "$build/issuer:/usr/local/bin/issuer:ro" \
	-v "$here/run.sh:/run.sh:ro" \
	weed-interop bash /run.sh
