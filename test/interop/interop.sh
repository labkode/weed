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
# Copied into the container: Landlock, which confines weed's workers, cannot follow
# the mounts of the host of Docker Desktop (macOS), which would keep them from
# executing weed
docker run --rm \
	-v "$build:/build:ro" \
	-v "$here/run.sh:/run.sh:ro" \
	weed-interop bash -c 'install /build/weed /build/issuer /usr/local/bin/ && exec bash /run.sh'
