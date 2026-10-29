#!/bin/sh
# The lab: weed serving 22 Unix accounts that authenticate with certificates, WLCG
# tokens and passwords, with limits per account and group, under a load that does not
# stop, in a privileged container (weed-lab), to watch /status, /metrics and the logs
# while it runs. It runs until removed (docker rm -f weed-lab); make lab-ssh opens a
# shell in it. Ports are published on this host's loopback only. Needs Go and Docker.
#
#     test/lab/lab.sh
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
mkdir "$build/lab" && cp "$here/run.sh" "$here/load.sh" "$here/creds.sh" "$build/lab/"

# The image of the interoperability tests has the clients, and openssl, jq, python3
docker build -q -t weed-interop "$root/test/interop" >/dev/null
docker rm -f weed-lab >/dev/null 2>&1 || true
docker create --name weed-lab --hostname weed-lab --privileged --tmpfs /data:size=3g \
	-p 127.0.0.1:9443:9443 -p 127.0.0.1:9100:9100 weed-interop bash /lab/run.sh >/dev/null
docker cp -q "$build/weed" weed-lab:/usr/local/bin/weed
docker cp -q "$build/issuer" weed-lab:/usr/local/bin/issuer
docker cp -q "$build/lab" weed-lab:/lab
docker start weed-lab >/dev/null

for i in $(seq 120); do
	curl -sf -o /dev/null http://localhost:9100/healthz && break
	if [ "$(docker inspect -f '{{.State.Running}}' weed-lab)" != true ] || [ $i = 120 ]; then
		docker logs weed-lab
		echo "the lab did not start" >&2
		exit 1
	fi
	sleep 0.5
done
mkdir -p "$here/out"
for f in ca.pem alice.pem alice.key; do docker cp -q weed-lab:/lab/pki/$f "$here/out/$f"; done
out=${here#"$root"/}/out
cat <<EOF
The lab runs: weed serves 22 accounts under a load that does not stop.

  http://localhost:9100/status    also /metrics, /healthz
  https://localhost:9443/webdav/  e.g. curl --cacert $out/ca.pem \\
                                    --cert $out/alice.pem --key $out/alice.key \\
                                    https://localhost:9443/proc/whoami
  docker logs -f weed-lab         the scenes of the load
  make lab-ssh                    a shell in the lab
  docker rm -f weed-lab           stops it
EOF
