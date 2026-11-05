package utils

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"
)

// The password file (basic.htpasswd) and the app tokens file (basic.app_tokens) that
// weed reads: weed utils password and token change them in place of an editor

// CheckUserName refuses a name that the files cannot hold
func CheckUserName(name string) error {
	if name == "" || strings.ContainsAny(name, ": \t\r\n") {
		return fmt.Errorf("invalid user name %q: it is not empty, and has no colon nor white space", name)
	}
	return nil
}

// SetPassword sets the password of user in the htpasswd file, adding the user if it
// is not there; replaced says whether it was
func SetPassword(file, name, password string) (replaced bool, err error) {
	if err := CheckUserName(name); err != nil {
		return false, err
	}
	if password == "" {
		return false, errors.New("the password is empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}
	line := name + ":" + string(hash)
	err = rewrite(file, func(lines []string) []string {
		var out []string
		for _, l := range lines {
			if userOf(l) == name {
				if !replaced {
					out = append(out, line) // where it was
				}
				replaced = true
				continue
			}
			out = append(out, l)
		}
		if !replaced {
			out = append(out, line)
		}
		return out
	})
	return replaced, err
}

// RemoveUser removes user from the htpasswd file; found says whether it was there
func RemoveUser(file, name string) (found bool, err error) {
	if err := CheckUserName(name); err != nil {
		return false, err
	}
	if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	err = rewrite(file, func(lines []string) []string {
		var out []string
		for _, l := range lines {
			if userOf(l) == name {
				found = true
				continue
			}
			out = append(out, l)
		}
		return out
	})
	return found, err
}

// userOf is the user of a line of an htpasswd file, "" for a comment or a blank line
func userOf(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	name, _, _ := strings.Cut(line, ":")
	return name
}

// AddToken adds token, of user, to the app tokens file ("token:user" lines)
func AddToken(file, name, token string) error {
	if err := CheckUserName(name); err != nil {
		return err
	}
	return rewrite(file, func(lines []string) []string { return append(lines, token+":"+name) })
}

// rewrite replaces file with its lines as edit changes them, at once (a temporary
// file renamed over it), so that weed, which may read it at any time, reads either.
// The file keeps its owner, group and mode; a new one is root's and readable by the
// group weed (0640) if there is one, as weed runs as the account weed, and by its
// owner alone (0600) otherwise.
func rewrite(file string, edit func(lines []string) []string) error {
	// The file that a symbolic link names, rather than the link
	if real, err := filepath.EvalSymlinks(file); err == nil {
		file = real
	}
	old, err := os.ReadFile(file)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var lines []string
	if s := strings.TrimRight(string(old), "\n"); s != "" {
		lines = strings.Split(s, "\n")
	}
	var b bytes.Buffer
	for _, l := range edit(lines) {
		b.WriteString(l + "\n")
	}

	mode, uid, gid := fs.FileMode(0o600), -1, -1
	if exists {
		fi, err := os.Stat(file)
		if err != nil {
			return err
		}
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	} else if g, err := user.LookupGroup("weed"); err == nil {
		if id, err := strconv.Atoi(g.Gid); err == nil {
			mode, gid = 0o640, id
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".new-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // unless renamed
	err = tmp.Chmod(mode)
	// Only root may give a file to another: others keep it theirs
	if err == nil && (uid >= 0 || gid >= 0) && os.Geteuid() == 0 {
		err = tmp.Chown(uid, gid)
	}
	if err == nil {
		_, err = tmp.Write(b.Bytes())
	}
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), file); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(file)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
