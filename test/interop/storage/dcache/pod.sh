# Chimera, dCache's namespace, is in PostgreSQL
before_storage() {
	podman run -d -q --pod $pod --name $pod-db -e POSTGRES_HOST_AUTH_METHOD=trust \
		-e POSTGRES_USER=dcache -e POSTGRES_DB=chimera docker.io/library/postgres:17.11 >/dev/null
}
