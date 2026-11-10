#!/bin/bash
# An XRootD redirector (xrootd and cmsd, HTTPS on port 1094) and a data server (port
# 1095), both with X.509, macaroons and HTTP-TPC. The redirector answers every request
# with a redirect to the data server, by the pod's hostname.
set -eu
CERTS=/etc/grid-security/certificates
mkdir -p $CERTS /etc/xrootd/tls /srv/x/interop /var/run/xrootd
cp /pki/ca.pem $CERTS/$(openssl x509 -hash -noout -in /pki/ca.pem).0
cp /pki/host.pem /pki/host.key /etc/xrootd/tls/
# The redirector and the data server must share the key: a macaroon that one of them
# gives out is checked by the other
openssl rand -base64 -out /etc/xrootd/macaroon-secret 64
printf '"%s" interop\n' "$(cat /pki/user.dn)" >/etc/xrootd/gridmap
echo "u interop /srv/x a" >/etc/xrootd/Authfile
chown -R xrootd /srv/x /etc/xrootd /var/run/xrootd
chmod 400 /etc/xrootd/tls/host.key /etc/xrootd/macaroon-secret

common() { # role xroot-and-https-port cmsd-port
	cat <<CFG
all.role $1
# By the pod's hostname, not localhost: the redirector sends clients to the data server
# by the name or address that it logged in with, and from localhost that is [::1] for
# a third-party COPY, which neon, in gfal2, does not match with the certificate
all.manager storage.interop.test:3121
all.export /srv/x
all.sitename interop
# Ready as soon as the data server has logged in
cms.delay startup 5 servers 1
if exec cmsd
xrd.port $3
fi
if exec xrootd
xrd.port $2
xrd.protocol XrdHttp:$2 libXrdHttp.so
xrd.tls /etc/xrootd/tls/host.pem /etc/xrootd/tls/host.key
xrd.tlsca certdir $CERTS
ofs.authorize 1
acc.authdb /etc/xrootd/Authfile
http.gridmap /etc/xrootd/gridmap
# The redirector sends HTTPS clients to the data server's HTTPS
http.desthttps yes
http.header2cgi Authorization authz
ofs.authlib ++ libXrdMacaroons.so
http.exthandler xrdmacaroons libXrdMacaroons.so
macaroons.secretkey /etc/xrootd/macaroon-secret
xrootd.chksum adler32
http.exthandler xrdtpc libXrdHttpTPC.so
# weed runs on localhost in this test
tpc.allow local
tpc.allow private
fi
CFG
}
common manager 1094 3121 >/etc/xrootd/redirector.cfg
common server 1095 3122 >/etc/xrootd/server.cfg
for n in redirector server; do
	for d in xrootd cmsd; do
		(cd /var/run/xrootd && $d -c /etc/xrootd/$n.cfg -n $n -l /var/log/xrootd/$d.log -R xrootd -b)
	done
done
sleep 2
tail -F /var/log/xrootd/*/*.log
