#!/bin/sh
# weed as a systemd service, installed from its RPM (packaging/, release/rpm.sh) as
# the guide says (docs/src/installation.md): in a privileged Podman container whose
# PID 1 is systemd, the RPM's unit, which runs weed as the account weed, with the
# sandboxing that the guide suggests; then as root (run.sh). The RPM is built in the
# container, of a weed built without cgo; WEED= builds it of that weed, such as a
# release's (release/dist.sh), and RPM= tests that RPM, such as a release's
# (release/rpm.sh). Needs Go, and Podman, which it runs as root (sudo).
#
#     [WEED=path | RPM=path] test/systemd/systemd.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
podman() { if [ "$(id -u)" = 0 ]; then command podman "$@"; else sudo podman "$@"; fi; }

build=$(mktemp -d)
name=weed-systemd-$$
trap 'podman rm -f $name >/dev/null 2>&1; rm -rf "$build"' EXIT
# What the RPM is built of, as the archive of a release has it, and how
mkdir "$build/pkg" "$build/src"
if [ -n "${RPM:-}" ]; then
	cp "$RPM" "$build/weed.rpm"
elif [ -n "${WEED:-}" ]; then
	cp "$WEED" "$build/pkg/weed"
else
	(cd "$root" && CGO_ENABLED=0 go build -o "$build/pkg/weed" .)
fi
cp "$root/README.txt" "$root/CHANGELOG.md" "$root/LICENSE" "$build/pkg/"
cp -R "$root/docs/html" "$build/pkg/guide"
cp -R "$root/packaging" "$root/release" "$build/src/"

podman build -q -t weed-systemd "$here" >/dev/null
podman run -d --name $name --privileged --systemd=always weed-systemd >/dev/null
# Copied into the container, not mounted, which SELinux would need labels for
put() { podman exec -i $name sh -c 'cat >"$1" && chmod "$2" "$1"' sh "$2" "$3" <"$1"; }
podman exec $name mkdir /test
put "$here/run.sh" /test/run.sh 0644
put "$root/docs/src/installation.md" /test/installation.md 0644
if [ -n "${RPM:-}" ]; then
	put "$build/weed.rpm" /test/weed.rpm 0644
else
	tar -C "$build" -cf - pkg src | podman exec -i $name tar -C /test -xf -
	podman exec $name sh -c 'cd /test/src && RELEASE=test release/rpm.sh /test/pkg 0.0.0 >/dev/null && cp dist/weed-*.rpm /test/weed.rpm'
fi
state=$(podman exec $name timeout 60 systemctl is-system-running --wait) || true
if [ "$state" != running ]; then
	podman exec $name systemctl --failed --no-pager >&2 || true
	echo "systemd did not boot: $state" >&2
	exit 1
fi
podman exec $name bash /test/run.sh
