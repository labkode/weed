#!/bin/sh
# weed as a systemd service, installed as the guide says (docs/src/installation.md): in
# a privileged container whose PID 1 is systemd, the unit of the guide with
# Delegate=yes and the sandboxing that the guide suggests, as root and then as an
# account of its own (run.sh). Needs Go and Docker.
#
#     test/systemd/systemd.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

case $(docker info --format '{{.Architecture}}') in
	x86_64 | amd64) goarch=amd64 ;;
	aarch64 | arm64) goarch=arm64 ;;
	*) echo "unsupported docker architecture" >&2; exit 1 ;;
esac
build=$(mktemp -d)
name=weed-systemd-$$
trap 'docker rm -f $name >/dev/null 2>&1; rm -rf "$build"' EXIT
(cd "$root" && GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o "$build/weed" .)

docker build -q -t weed-systemd "$here" >/dev/null
docker run -d --name $name --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock weed-systemd >/dev/null
# Copied into the container, not mounted: Landlock cannot follow the mounts of the host
# of Docker Desktop (macOS)
docker exec $name mkdir /test
docker cp -q "$build/weed" $name:/usr/local/bin/weed
docker cp -q "$here/run.sh" $name:/test/run.sh
docker cp -q "$root/docs/src/installation.md" $name:/test/installation.md
state=$(docker exec $name timeout 60 systemctl is-system-running --wait) || true
if [ "$state" != running ]; then
	docker exec $name systemctl --failed --no-pager >&2 || true
	echo "systemd did not boot: $state" >&2
	exit 1
fi
docker exec $name bash /test/run.sh
