package server

import "syscall"

// onRootFS reports whether dir is on the file system of /. Not whether it is a mount
// point: systemd's ReadWritePaths= bind-mounts it onto itself, the directory beneath
// an unmounted storage included.
func onRootFS(dir string) (bool, error) {
	var d, root syscall.Stat_t
	if err := syscall.Stat(dir, &d); err != nil {
		return false, err
	}
	if err := syscall.Stat("/", &root); err != nil {
		return false, err
	}
	return d.Dev == root.Dev, nil
}
