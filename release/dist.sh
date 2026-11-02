#!/bin/sh
# The archive of a release for this machine's architecture, in dist/: weed built with
# cgo, so that it looks accounts up as the system does (LDAP, SSSD), with README.txt,
# CHANGELOG.md, LICENSE and the guide (guide/); and SHA256SUMS. On EL10, which weed
# targets: weed built on a newer C library would not run there (CI builds on
# AlmaLinux 10, on a runner of each architecture). The commit must be a release:
# tagged vMAJOR.MINOR.PATCH, without changes, with its version the first section of
# CHANGELOG.md and in the guide. Needs Go and gcc.
#
#     release/dist.sh
set -eu
cd "$(dirname "$0")/.."
fail() { echo "release/dist.sh: $*" >&2; exit 1; }

. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
*" rhel "*) test "${VERSION_ID%%.*}" = 10 ;;
*) false ;;
esac || fail "releases are built on EL10 (AlmaLinux, RHEL or Rocky Linux 10), not on ${PRETTY_NAME:-this system}"

version=$(git describe --tags --exact-match --match 'v*' 2>/dev/null) ||
	fail "the commit has no tag v..., which a release is"
echo "$version" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+' || fail "$version is not vMAJOR.MINOR.PATCH"
# Go takes a tag from v2 on for the version only if the module's path ends in its major
major=${version%%.*}
module=$(awk '$1 == "module" { print $2 }' go.mod)
if [ "${major#v}" -ge 2 ] && [ "${module##*/}" != "$major" ]; then
	fail "the module of $version is github.com/labkode/weed/$major (go.mod and the imports), not $module"
fi
# Untracked files too: weed's version would end in +dirty
test -z "$(git status --porcelain)" || fail "the checkout has changes: $(git status --porcelain | head -3)"
test "$(awk '$1 == "##" { print $2; exit }' CHANGELOG.md)" = "$version" ||
	fail "the first section of CHANGELOG.md is not ## $version (date)"
grep -q ">for weed $version<" docs/html/index.html || fail "the guide is not for $version: make docs"

arch=$(go env GOARCH)
case $arch in
amd64 | arm64) ;;
*) fail "weed is not built for $arch" ;;
esac
name=weed-$version-linux-$arch
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/$name"
echo "== $name"
CGO_ENABLED=1 GOTOOLCHAIN=local go build -trimpath -o "$work/$name/weed" .
"$work/$name/weed" version
got=$(go version -m "$work/$name/weed" | awk '$1 == "mod" { print $3 }')
test "$got" = "$version" || fail "weed says it is $got, not $version"
cp README.txt CHANGELOG.md LICENSE "$work/$name/"
cp -R docs/html "$work/$name/guide"
mkdir -p dist
tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner --mtime="$(git log -1 --format=%cI)" \
	-cf - "$name" | gzip -n >"dist/$name.tar.gz"
(cd dist && sha256sum weed-*.tar.gz >SHA256SUMS && cat SHA256SUMS)
