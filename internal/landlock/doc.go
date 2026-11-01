// Package landlock confines a thread, and the processes it starts, to some files and
// directories with Linux's Landlock: beneath none of them can it read, write, create,
// remove or execute anything, whatever the permissions. It needs Linux 5.19 or later
// (Landlock ABI 2), with landlock among the security modules (lsm=).
package landlock
