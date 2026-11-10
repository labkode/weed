#!/bin/bash
# Interoperability with another WLCG storage system: weed and the system copy files to
# each other, with both of them pulling and pushing, driven by gfal2 with an X.509
# proxy (storage/run.sh). The system runs from storage/<name>/: its Containerfile, the
# start.sh that it runs with the test certificates in /pki, and test.env, which says
# where the test writes in it. Its containers, the test container (weed-interop) and
# weed share a Podman pod, so that all of them are on localhost, and on its hostname.
# Needs Go, and Podman, which it runs as root (sudo), or as yourself with ROOTLESS=1.
#
#     test/interop/storage.sh dcache
#
# storage/<name>/pod.sh, if there is one, defines before_storage, which starts what the
# system needs besides its own container, such as a database, with $pod set.
set -eu
name=${1:?usage: $0 <storage> (one of: $(ls "$(dirname "$0")/storage" | grep -v '\.' | tr '\n' ' '))}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
dir=$here/storage/$name
[ -f "$dir/Containerfile" ] || { echo "no storage $name: $dir/Containerfile is missing" >&2; exit 2; }
podman() { if [ "$(id -u)" = 0 ] || [ "${ROOTLESS:-}" = 1 ]; then command podman "$@"; else sudo podman "$@"; fi; }

pod=weed-$name-$$
build=$(mktemp -d)
status=1
cleanup() {
	if [ $status != 0 ]; then
		for c in $(podman ps -a --pod --filter pod=$pod --format '{{.Names}}' | grep -v infra); do
			echo "--- tail of the logs of $c"
			podman logs --tail 60 $c 2>&1
		done
	fi
	podman pod rm -f $pod >/dev/null 2>&1 || true
	podman volume rm -f $pod-pki >/dev/null 2>&1 || true
	rm -rf "$build"
}
trap cleanup EXIT

(cd "$root" && CGO_ENABLED=0 go build -o "$build/weed" .)
cp "$here/lib.sh" "$here/storage/run.sh" "$build/"
podman build -q -t weed-interop "$here" >/dev/null
podman build -q -t weed-storage-$name "$dir" >/dev/null

before_storage() { :; }
[ -f "$dir/pod.sh" ] && . "$dir/pod.sh"
podman pod create --name $pod --hostname storage.interop.test >/dev/null
podman volume create $pod-pki >/dev/null
# The certificates, for everyone
tar -C "$build" -cf - lib.sh | podman run --rm -i -v $pod-pki:/pki weed-interop bash -c \
	'mkdir /build && tar -x -C /build && cd /pki && . /build/lib.sh && make_pki && echo "$USER_DN" >user.dn && chmod -R a+r /pki'

before_storage
podman run -d -q --pod $pod --name $pod-$name -v $pod-pki:/pki:ro weed-storage-$name >/dev/null

# Copied into the container, not mounted, which SELinux would need labels for
tar -C "$build" -cf - weed lib.sh run.sh | podman run --rm -i --pod $pod -v $pod-pki:/pki:ro \
	--env-file "$dir/test.env" -e STORAGE=$name weed-interop bash -c \
	'mkdir /build && tar -x -C /build && install /build/weed /usr/local/bin/ && exec bash /build/run.sh </dev/null'
status=$?
