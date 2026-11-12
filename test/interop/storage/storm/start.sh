#!/bin/sh
# Runs StoRM WebDAV with the test certificates of /pki: HTTPS on port 8543, the storage
# area /interop in /srv/storm/interop, which the test user's DN may read and write
set -eu
G=/etc/grid-security
cp /pki/ca.pem $G/certificates/$(openssl x509 -hash -noout -in /pki/ca.pem).0
cp /pki/*.r0 /pki/*.namespaces /pki/*.signing_policy $G/certificates/
cp /pki/host.pem $G/storm-webdav/hostcert.pem
cp /pki/host.key $G/storm-webdav/hostkey.pem
chmod 400 $G/storm-webdav/hostkey.pem
# The VO interop, whose VOMS proxies the test makes with the host certificate (see
# make_voms_proxy): StoRM gives macaroons only to clients with a VOMS proxy
dn() { openssl x509 -noout -subject -nameopt compat -in $1 | sed 's/^subject=//'; }
mkdir -p $G/vomsdir/interop
printf '%s\n%s\n' "$(dn /pki/host.pem)" "$(dn /pki/ca.pem)" >$G/vomsdir/interop/localhost.lsc
# StoRM compares the DN in the RFC 2253 form, CN=...,DC=org
subject=$(openssl x509 -noout -subject -nameopt RFC2253 -in /pki/user.pem | sed 's/^subject=//')

cat >/etc/storm/webdav/sa.d/interop.properties <<SA
name=interop
rootPath=/srv/storm/interop
filesystemType=posixfs
accessPoints=/interop
anonymousReadEnabled=false
authenticatedReadEnabled=false
fineGrainedAuthzEnabled=true
SA
cat >/etc/storm/webdav/config/application.yml <<YML
storm:
  hostnames:
    - storage.interop.test
  authz:
    policies:
      - sa: interop
        description: the test user
        actions:
          - all
        effect: permit
        paths:
          - /**
        principals:
          - type: x509-subject
            params:
              subject: "$subject"
YML

export STORM_WEBDAV_HTTPS_PORT=8543
# Tokens and macaroons, for third-party copies, come without a client certificate
export STORM_WEBDAV_REQUIRE_CLIENT_CERT=false
# Macaroons, which gfal2 asks for, are tokens of StoRM's own authorization server
export STORM_WEBDAV_AUTHZ_SERVER_ENABLE=true
cd /
exec java -Dspring.config.additional-location=file:/etc/storm/webdav/config/ \
	-cp 'app:app/lib/*' org.italiangrid.storm.webdav.WebdavService
