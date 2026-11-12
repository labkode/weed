#!/bin/bash
# QuarkDB, an MGM and an FST, as eos daemon runs them, with the test certificates of
# /pki: HTTPS on the MGM's port 9000, which sends clients to the FST's 9001, X.509
# users mapped by a grid-mapfile, macaroons and HTTP-TPC on both. The test user,
# interop, owns /eos/dev/interop, which appears once EOS can write to the FST.
set -eu
G=/etc/grid-security
mkdir -p $G/certificates $G/daemon /data/fst/01
cp /pki/ca.pem $G/certificates/$(openssl x509 -hash -noout -in /pki/ca.pem).0
cp /pki/*.r0 /pki/*.namespaces /pki/*.signing_policy $G/certificates/
cp /pki/host.pem $G/daemon/hostcert.pem
cp /pki/host.key $G/daemon/hostkey.pem
useradd -u 7001 interop
printf '"%s" interop\n' "$(cat /pki/user.dn)" >$G/grid-mapfile
openssl rand -base64 -out /etc/eos.macaroon.secret 64
chown daemon: $G/daemon/* /etc/eos.macaroon.secret /data/fst/01
chmod 400 $G/daemon/hostkey.pem /etc/eos.macaroon.secret

http() { # port: XrdHttp with TLS and HTTP-TPC
	cat <<CFG
xrd.protocol XrdHttp:$1 libXrdHttp.so
xrd.tls $G/daemon/hostcert.pem $G/daemon/hostkey.pem
xrd.tlsca certdir $G/certificates/
http.exthandler xrdtpc libXrdHttpTPC.so
# weed runs on localhost in this test
tpc.allow local
tpc.allow private
CFG
}
# eos daemon reads each service's xrootd configuration from its [<service>:xrootd:...]
# section, and its environment from [sysconfig]
C=/etc/eos/config
{
	sed '/^\[sysconfig\]/,$d' $C/mgm/mgm
	http 9000
	cat <<CFG
http.gridmap $G/grid-mapfile
http.exthandler EosMgmHttp libEosMgmHttp.so eos::mgm::http::redirect-to-https=1
mgmofs.macaroonslib libXrdMacaroons.so
macaroons.secretkey /etc/eos.macaroon.secret
all.sitename eosdev
CFG
	sed -n '/^\[sysconfig\]/,$p' $C/mgm/mgm
} >$C/mgm/mgm.new
mv $C/mgm/mgm.new $C/mgm/mgm
sed -i 's/^\[sysconfig\]$/&\nEOS_FST_HTTP_PORT=9001/' $C/fst/fst
# (the file does not end with a newline)
{
	echo
	http 9001
	echo "http.exthandler EosFstHttp libEosFstHttp.so none"
} >>$C/fst/fst

export EOS_MGM_URL=root://localhost
eos daemon sss recreate >/dev/null
eos daemon run qdb >/var/log/eos-qdb.out 2>&1 &
eos daemon run mgm >/var/log/eos-mgm.out 2>&1 &
until eos -b ns >/dev/null 2>&1; do sleep 1; done
eos daemon run fst >/var/log/eos-fst.out 2>&1 &

# The filesystem, which EOS takes on the root partition only with these files
echo fs-01 >/data/fst/01/.eosfsuuid
echo 1 >/data/fst/01/.eosfsid
chown daemon: /data/fst/01/.eosfs*
eos -b space define default 1 1
eos -b fs add -m 1 fs-01 storage.interop.test:1095 /data/fst/01 default.0 rw
eos -b node set storage.interop.test:1095 on
eos -b group set default.0 on
eos -b space set default on
until eos -b fs ls -m | grep -q 'stat.boot=booted.*stat.active=online\|stat.active=online.*stat.boot=booted'; do
	sleep 1
done
# EOS places files on a filesystem some seconds after it is online: until it does,
# uploads fail
echo probe >/tmp/probe
until eos -b cp /tmp/probe /eos/dev/probe >/dev/null 2>&1; do
	sleep 1
done
eos -b rm /eos/dev/probe
# HTTPS users are who the grid-mapfile says
eos -b vid enable https
eos -b mkdir -p /eos/dev/interop
eos -b chown 7001:7001 /eos/dev/interop
echo "EOS is ready"
tail -F /var/log/eos-*.out
