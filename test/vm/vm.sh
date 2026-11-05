#!/bin/sh
# weed's RPM on an AlmaLinux 10 virtual machine, as on a server: EL10's kernel,
# systemd booted, SELinux enforcing, as the cloud image has them. In it, the tests of
# make test-systemd (test/systemd/run.sh) run as in their container, then
# test/vm/guest.sh checks that SELinux denied weed nothing. The RPM is built of a weed
# built without cgo, in a container (Podman), as make test-systemd builds it; RPM=
# tests that RPM, such as a release's (release/rpm.sh).
#
# Needs qemu-system-x86_64 with KVM (/dev/kvm), qemu-img, curl, xorriso or
# genisoimage, and Go and Podman to build the RPM. The cloud image is kept in
# ~/.cache/weed-vm (VM_CACHE=).
#
#     [RPM=path] test/vm/vm.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
images=https://repo.almalinux.org/almalinux/10/cloud/x86_64/images
image=AlmaLinux-10-GenericCloud-latest.x86_64.qcow2
cache=${VM_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/weed-vm}

[ -w /dev/kvm ] || { echo "vm.sh needs KVM: /dev/kvm is missing, or not writable" >&2; exit 1; }
for c in qemu-system-x86_64 qemu-img curl; do
	command -v $c >/dev/null || { echo "vm.sh needs $c" >&2; exit 1; }
done
if command -v xorriso >/dev/null; then
	iso() { xorriso -as mkisofs -quiet -V cidata -J -r -o "$1" "$2"; }
elif command -v genisoimage >/dev/null; then
	iso() { genisoimage -quiet -V cidata -J -r -o "$1" "$2"; }
else
	echo "vm.sh needs xorriso or genisoimage" >&2
	exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/seed"

# The RPM
if [ -n "${RPM:-}" ]; then
	cp "$RPM" "$work/seed/weed.rpm"
else
	mkdir "$work/pkg" "$work/src"
	(cd "$root" && CGO_ENABLED=0 go build -o "$work/pkg/weed" .)
	cp "$root/README.txt" "$root/CHANGELOG.md" "$root/LICENSE" "$work/pkg/"
	cp -R "$root/docs/html" "$work/pkg/guide"
	cp -R "$root/packaging" "$root/release" "$work/src/"
	podman run --rm -v "$work:/b:Z" almalinux:10 sh -c '
		dnf -q -y install rpm-build systemd-rpm-macros >/dev/null &&
		cd /b/src && RELEASE=test release/rpm.sh /b/pkg 0.0.0 >/dev/null && cp dist/weed-*.rpm /b/seed/weed.rpm'
fi

# The cloud image, checked against the checksums that AlmaLinux publishes
mkdir -p "$cache"
curl -fsSL -o "$cache/CHECKSUM" "$images/CHECKSUM"
want=$(awk -v f="($image)" '$1 == "SHA256" && $2 == f { print $4 }' "$cache/CHECKSUM")
[ -n "$want" ] || want=$(awk -v f="$image" '$2 == f || $2 == "*"f { print $1 }' "$cache/CHECKSUM")
if [ ! -f "$cache/$image" ] || [ "$(sha256sum <"$cache/$image" | cut -d' ' -f1)" != "$want" ]; then
	echo "vm.sh: downloading $image" >&2
	curl -fsSL -o "$cache/$image.part" "$images/$image"
	[ "$(sha256sum <"$cache/$image.part" | cut -d' ' -f1)" = "$want" ] ||
		{ echo "vm.sh: $image does not match its checksum" >&2; exit 1; }
	mv "$cache/$image.part" "$cache/$image"
fi
qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$image" "$work/disk.qcow2" 20G

# cloud-init (NoCloud): the seed's files go to /test, and guest.sh runs, in a unit of
# its own, once the boot is over; its output is the second serial port's
cp "$here/../systemd/run.sh" "$root/docs/src/installation.md" "$here/guest.sh" "$work/seed/"
echo "instance-id: weed-vm" >"$work/seed/meta-data"
cat >"$work/seed/user-data" <<'EOF'
#cloud-config
runcmd:
  - [sh, -c, "mkdir -p /test /mnt/seed && mount -o ro LABEL=cidata /mnt/seed && cp /mnt/seed/* /test/ && systemd-run --no-block --unit weed-vm-test sh /test/guest.sh"]
EOF
iso "$work/seed.iso" "$work/seed"

echo "vm.sh: booting AlmaLinux 10 (console: $work/console.log)" >&2
: >"$work/test.log"
tail -f "$work/test.log" &
tailer=$!
status=0
timeout 45m qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 2 -m 4096 \
	-drive file="$work/disk.qcow2",if=virtio -drive file="$work/seed.iso",media=cdrom,readonly=on \
	-netdev user,id=net -device virtio-net-pci,netdev=net \
	-display none -serial file:"$work/console.log" -serial file:"$work/test.log" ||
	status=$?
sleep 1
kill $tailer 2>/dev/null || true
if [ $status != 0 ]; then
	echo "vm.sh: the VM did not power off (qemu: $status); its console ends with:" >&2
	tail -30 "$work/console.log" >&2
	exit 1
fi
# The serial port's tty ends lines with \r\n
tr -d '\r' <"$work/test.log" | grep -qx 'weed-vm: ok' || { echo "vm.sh: the tests failed" >&2; exit 1; }
