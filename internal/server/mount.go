package server

import "fmt"

// checkMounted refuses dir if it is on the file system of / (server.require_mount):
// the directory beneath a storage that is not mounted would take the uploads, and
// show an empty namespace
func checkMounted(dir string) error {
	root, err := onRootFS(dir)
	if err != nil {
		return fmt.Errorf("cannot tell whether the storage of the exported directory %s is mounted (server.require_mount): %w", dir, err)
	}
	if root {
		return fmt.Errorf("the exported directory %s is on the file system of /, not on a storage of its own (server.require_mount): is its storage mounted?", dir)
	}
	return nil
}
