#!/bin/bash
# Runs dCache, as the account dcache, with the test certificates of /pki, once
# PostgreSQL is up, and makes /data/interop for the test user
set -eu
G=/etc/grid-security
# The CA's hash, from the name of its CRL: the image has no openssl
crl=$(ls /pki/*.r0)
cp /pki/ca.pem $G/certificates/$(basename $crl .r0).0
cp $crl /pki/*.namespaces /pki/*.signing_policy $G/certificates/
cp /pki/host.pem $G/hostcert.pem
cp /pki/host.key $G/hostkey.pem
chmod 400 $G/hostkey.pem
printf 'dn:"%s" username:interop uid:1000 gid:1000,true\n' "$(cat /pki/user.dn)" >/etc/dcache-interop/multi-mapfile
echo 'username:interop root:/ home:/data/interop' >/etc/dcache-interop/omnisession.conf

until (exec 3<>/dev/tcp/localhost/5432) 2>/dev/null; do sleep 1; done
/run.sh core &
dcache=$!

# Chimera's schema is made when the namespace starts
chimera() { /opt/dcache/bin/chimera "$@"; }
until chimera ls / >/dev/null 2>&1; do sleep 2; done
chimera mkdir /data
chimera mkdir /data/interop
chimera chown 1000:1000 /data/interop
echo "dcache-interop: /data/interop made"
wait $dcache
