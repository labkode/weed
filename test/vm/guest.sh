#!/bin/sh
# In the virtual machine of test/vm/vm.sh, as root, once it has booted: the tests of
# make test-systemd, then that SELinux denied weed nothing. Its output is the second
# serial port, which vm.sh shows; it ends with "weed-vm: ok" if all passed, and
# powers the machine off.
exec >/dev/ttyS1 2>&1
fail() {
	echo "weed-vm: $*"
	echo "weed-vm: failed"
	systemctl poweroff
	exit 1
}
systemctl is-system-running --wait >/dev/null
echo "weed-vm: $(. /etc/os-release && echo "$PRETTY_NAME"), Linux $(uname -r), SELinux $(getenforce), systemd $(systemctl --version | awk 'NR == 1 { print $2 }')"
[ "$(getenforce)" = Enforcing ] || fail "SELinux is not enforcing"

# What run.sh uses, beyond the cloud image. A mirror may serve broken metadata for a
# while ("repomd.xml parser error"): dnf reads only the repositories it needs, and
# tries again
for i in 1 2 3 4; do
	dnf -q -y --repo=baseos --repo=appstream install jq diffutils logrotate procps-ng util-linux curl audit >/dev/null && break
	[ $i = 4 ] && fail "cannot install run.sh's tools"
	echo "weed-vm: dnf failed, trying again in $((i * 15))s"
	dnf -q clean metadata; sleep $((i * 15))
done

bash /test/run.sh
status=$?

# weed, its starter and its workers, which systemd runs unconfined (unconfined_service_t)
systemctl start weed && echo "weed-vm: weed runs as $(ps -o label= -C weed | sort -u | tr '\n' ' ')"
systemctl stop weed
echo "weed-vm: SELinux denials of weed's processes:"
denials=$({
	ausearch -m AVC,USER_AVC,SELINUX_ERR -ts boot -i 2>/dev/null
	journalctl -k -b -o cat | grep 'avc:'
} | grep -E 'comm=.?weed|exe=.?/usr/bin/weed' | sort -u || true)
echo "${denials:-none}"
[ -z "$denials" ] || status=1
[ $status = 0 ] || fail "run.sh failed, or SELinux denied weed"
echo "weed-vm: ok"
systemctl poweroff
