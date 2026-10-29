#!/bin/sh
# The lab: weed serving 22 Unix accounts that authenticate with certificates, WLCG
# tokens and passwords, with limits per account and group, under a load that does not
# stop, in a privileged container (weed-lab), to watch its dashboard, /status,
# /metrics and the logs while it runs; and Prometheus and Grafana, with the dashboard
# of grafana/weed.json, in two more containers. It runs until make lab-stop; make
# lab-ssh opens a shell in weed's container. Ports are published on this host's
# loopback only. Needs Go and Docker.
#
#     test/lab/lab.sh         starts it, again if it runs
#     test/lab/lab.sh stop    stops it
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
PROMETHEUS=prom/prometheus:v3.5.0
GRAFANA=grafana/grafana:12.1.0

stop() {
	docker rm -fv weed-lab weed-lab-prometheus weed-lab-grafana >/dev/null 2>&1 || true
	docker network rm weed-lab >/dev/null 2>&1 || true
}
if [ "${1:-}" = stop ]; then
	for c in weed-lab weed-lab-prometheus weed-lab-grafana; do
		if docker inspect $c >/dev/null 2>&1; then
			stop
			echo "the lab is stopped"
			exit 0
		fi
	done
	docker network rm weed-lab >/dev/null 2>&1 || true
	echo "the lab does not run"
	exit 0
fi

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
mkdir -p "$build/grafana/provisioning/datasources" "$build/grafana/provisioning/dashboards" "$build/grafana/dashboards"
cp "$here/grafana/datasource.yml" "$build/grafana/provisioning/datasources/weed.yml"
cp "$here/grafana/dashboards.yml" "$build/grafana/provisioning/dashboards/weed.yml"
cp "$here/grafana/weed.json" "$build/grafana/dashboards/weed.json"

# The image of the interoperability tests has the clients, and openssl, jq, python3
docker build -q -t weed-interop "$root/test/interop" >/dev/null
docker pull -q $PROMETHEUS >/dev/null
docker pull -q $GRAFANA >/dev/null
stop
docker network create weed-lab >/dev/null

docker create --name weed-lab --hostname weed-lab --network weed-lab --privileged --tmpfs /data:size=3g \
	-p 127.0.0.1:9443:9443 -p 127.0.0.1:9100:9100 weed-interop bash /lab/run.sh >/dev/null
docker cp -q "$build/weed" weed-lab:/usr/local/bin/weed
docker cp -q "$build/issuer" weed-lab:/usr/local/bin/issuer
docker cp -q "$build/lab" weed-lab:/lab

docker create --name weed-lab-prometheus --network weed-lab -p 127.0.0.1:9090:9090 $PROMETHEUS \
	--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus \
	--storage.tsdb.retention.time=2d >/dev/null
docker cp -q "$here/grafana/prometheus.yml" weed-lab-prometheus:/etc/prometheus/prometheus.yml

# Grafana without logins: whoever reaches this host's loopback administers it
docker create --name weed-lab-grafana --network weed-lab -p 127.0.0.1:3000:3000 \
	-e GF_AUTH_ANONYMOUS_ENABLED=true -e GF_AUTH_ANONYMOUS_ORG_ROLE=Admin -e GF_AUTH_DISABLE_LOGIN_FORM=true \
	-e GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/etc/grafana/dashboards/weed.json \
	-e GF_ANALYTICS_REPORTING_ENABLED=false -e GF_ANALYTICS_CHECK_FOR_UPDATES=false \
	-e GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false -e GF_NEWS_NEWS_FEED_ENABLED=false \
	$GRAFANA >/dev/null
docker cp -q "$build/grafana/." weed-lab-grafana:/etc/grafana/

docker start weed-lab weed-lab-prometheus weed-lab-grafana >/dev/null

# up URL NAME CONTAINER: waits for URL to answer while CONTAINER runs
up() {
	for i in $(seq 120); do
		curl -sf -o /dev/null "$1" && return 0
		if [ "$(docker inspect -f '{{.State.Running}}' "$3")" != true ] || [ $i = 120 ]; then
			docker logs "$3" 2>&1 | tail -30
			echo "$2 did not start" >&2
			exit 1
		fi
		sleep 0.5
	done
}
up http://localhost:9100/healthz weed weed-lab
up http://localhost:9090/-/ready Prometheus weed-lab-prometheus
up http://localhost:3000/api/health Grafana weed-lab-grafana
mkdir -p "$here/out"
for f in ca.pem alice.pem alice.key; do docker cp -q weed-lab:/lab/pki/$f "$here/out/$f"; done
out=${here#"$root"/}/out
cat <<EOF
The lab runs: weed serves 22 accounts under a load that does not stop.

  http://localhost:9100/          weed's dashboard; also /status, /metrics, /healthz
  http://localhost:3000/          Grafana, with the dashboard of weed's metrics
  http://localhost:9090/          Prometheus, which scrapes weed every 5 seconds
  https://localhost:9443/webdav/  e.g. curl --cacert $out/ca.pem \\
                                    --cert $out/alice.pem --key $out/alice.key \\
                                    https://localhost:9443/proc/whoami
  docker logs -f weed-lab         the scenes of the load
  make lab-ssh                    a shell in the lab
  make lab-stop                   stops it
EOF
