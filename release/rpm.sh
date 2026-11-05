#!/bin/sh
# The RPM of a release, in dist/, from the archive that release/dist.sh made, or a
# directory that holds what the archive does (weed, README.txt, CHANGELOG.md, LICENSE,
# guide/): weed-VERSION-RELEASE.el10.ARCH.rpm, with the account weed, its systemd
# unit, a configuration in /etc/weed, and its sysctl settings (packaging/). On EL10,
# with rpm-build and systemd-rpm-macros. VERSION is the archive's (vX.Y.Z), or $2 for
# a directory; RELEASE is 1, or $RELEASE.
#
#     release/rpm.sh dist/weed-v1.2.0-linux-amd64.tar.gz
#     RELEASE=test release/rpm.sh DIR 0.0.0
set -eu
cd "$(dirname "$0")/.."
fail() { echo "release/rpm.sh: $*" >&2; exit 1; }
[ $# -ge 1 ] || fail "usage: release/rpm.sh ARCHIVE | DIR VERSION"
command -v rpmbuild >/dev/null || fail "needs rpmbuild (dnf install rpm-build systemd-rpm-macros)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
case $1 in
*.tar.gz)
	name=$(basename "$1" .tar.gz)
	version=$(echo "$name" | sed -n 's/^weed-v\([0-9]*\.[0-9]*\.[0-9]*\)-linux-[a-z0-9]*$/\1/p')
	[ -n "$version" ] || fail "$1 is not the archive of a release, weed-vX.Y.Z-linux-ARCH.tar.gz"
	tar -xzf "$1" -C "$work"
	dir=$work/$name
	;;
*)
	[ $# -eq 2 ] || fail "a directory needs a version: release/rpm.sh DIR VERSION"
	dir=$(cd "$1" && pwd) version=$2
	;;
esac
for f in weed README.txt CHANGELOG.md LICENSE guide; do
	[ -e "$dir/$f" ] || fail "$dir has no $f"
done
# The architecture of the RPM is weed's: e_machine, in its ELF header
case $(od -An -tx1 -j18 -N2 "$dir/weed" | tr -d ' \n') in
3e00) target=x86_64 ;;
b700) target=aarch64 ;;
*) fail "$dir/weed is not weed for amd64 or arm64" ;;
esac

rpmbuild -bb --quiet --target "$target" packaging/weed.spec \
	--define "_topdir $work/rpmbuild" --define "_sourcedir $PWD/packaging" \
	--define "weed_version $version" --define "weed_dir $dir" ${RELEASE:+--define "weed_release $RELEASE"} >/dev/null
mkdir -p dist
for f in "$work"/rpmbuild/RPMS/*/weed-*.rpm; do
	cp "$f" dist/
	echo "dist/${f##*/}"
done
