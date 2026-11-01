#!/bin/bash
# make find-limits (see lab.sh): stress against weed in its own container, as the
# lab's accounts; the arguments go to stress (stress -h), e.g. -scenarios download
set -eu
while read -r name kind; do
	case $kind in
	x509) echo "$name cert /lab/pki/$name.pem /lab/pki/$name.key" ;;
	basic) echo "$name basic lab-$name" ;;
	token) echo "$name bearer @/lab/tokens/$name" ;;
	esac
done </lab/accounts >/lab/identities
exec stress -identities /lab/identities -as alice -url 'https://localhost:9443/webdav/{user}' \
	-ca /lab/pki/ca.pem -cgroup /sys/fs/cgroup/weed -status http://localhost:9100/status \
	-report /lab/limits.txt -json /lab/limits.json "$@"
