#!/bin/sh
# weed as a systemd service, installed as the guide says (docs/src/installation.md): in
# a privileged Podman container whose PID 1 is systemd, the unit of the guide with
# Delegate=yes and the sandboxing that the guide suggests, as root and then as an
# account of its own (run.sh). WEED= tests that weed, such as a release's
# (release/dist.sh), rather than one built without cgo. Needs Go, and Podman, which it
# runs as root (sudo).
#
#     [WEED=path] test/systemd/systemd.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
podman() { if [ "$(id -u)" = 0 ]; then command podman "$@"; else sudo podman "$@"; fi; }

build=$(mktemp -d)
name=weed-systemd-$$
trap 'podman rm -f $name >/dev/null 2>&1; rm -rf "$build"' EXIT
if [ -n "${WEED:-}" ]; then
	cp "$WEED" "$build/weed"
else
	(cd "$root" && CGO_ENABLED=0 go build -o "$build/weed" .)
fi

podman build -q -t weed-systemd "$here" >/dev/null
podman run -d --name $name --privileged --systemd=always weed-systemd >/dev/null
# Copied into the container, not mounted, which SELinux would need labels for
put() { podman exec -i $name sh -c 'cat >"$1" && chmod "$2" "$1"' sh "$2" "$3" <"$1"; }
podman exec $name mkdir /test
put "$build/weed" /usr/local/bin/weed 0755
put "$here/run.sh" /test/run.sh 0644
put "$root/docs/src/installation.md" /test/installation.md 0644
state=$(podman exec $name timeout 60 systemctl is-system-running --wait) || true
if [ "$state" != running ]; then
	podman exec $name systemctl --failed --no-pager >&2 || true
	echo "systemd did not boot: $state" >&2
	exit 1
fi
podman exec $name bash /test/run.sh
