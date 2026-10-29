# The credentials of the lab's accounts (see run.sh), for load.sh and the lab's shell.
# auth_of ACCOUNT sets u to the account, A to its curl arguments, and T to what its
# third-party copies pass in TransferHeaderAuthorization ("" for certificates).
declare -A KIND
while read -r name kind; do KIND[$name]=$kind; done </lab/accounts

auth_of() {
	u=$1
	case ${KIND[$u]:-} in
	x509) A=(--cert /lab/pki/$u.pem --key /lab/pki/$u.key) T="" ;;
	basic) A=(-u "$u:lab-$u") T="Basic $(printf '%s' "$u:lab-$u" | base64)" ;;
	token) A=(-H "Authorization: Bearer $(</lab/tokens/$u)") T="Bearer $(</lab/tokens/$u)" ;;
	*) echo "$u is not an account of the lab (/lab/accounts)" >&2; return 1 ;;
	esac
}
