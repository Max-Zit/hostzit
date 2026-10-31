package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// System is what the operations do to the machine. OS is the real one;
// tests use OS with a temporary root and a recording runner.
type System interface {
	// WriteFile replaces a file atomically (only below writablePrefixes).
	WriteFile(path string, data []byte, mode os.FileMode, uid, gid int) error
	ReadFile(path string) ([]byte, error)
	Remove(path string) error
	RemoveAll(path string) error
	// Mkdir creates a directory (and missing parents, root-owned) and sets
	// the owner and mode of the last one.
	Mkdir(path string, mode os.FileMode, uid, gid int) error
	Exists(path string) bool
	// Run starts a program with an argument list (never a shell).
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
	Mount(m MountReq) error
	Unmount(target string) error
	Mounted(target string) bool
	Mknod(path string, major, minor uint32) error
	Symlink(target, path string) error
	ReadDir(path string) ([]os.DirEntry, error)
}

// MountReq is a bind mount or a proc mount.
type MountReq struct {
	Source, Target string
	ReadOnly       bool
	Proc           bool // mount a new proc with hidepid=invisible
}

// writablePrefixes are the only places the helper writes files as root.
// Nothing below /home is on the list: inside account homes the worker
// does the work as the account.
var writablePrefixes = []string{
	"/etc/nginx/zit.d/hostzit/", "/etc/nginx/conf.d/hostzit.conf", "/etc/systemd/system/hz-", "/etc/systemd/system/user-",
	"/var/lib/hostzit/", "/var/cache/hostzit/", "/var/log/hostzit/", "/etc/ssh/sshd_config.d/hostzit.conf",
	"/usr/share/hostzit/", "/var/lib/zit-acme/", "/etc/nftables.d/hostzit.nft", "/etc/hostzit/",
	"/etc/mysql/mariadb.conf.d/90-hostzit.cnf", "/etc/powerdns/pdns.d/hostzit.conf", "/etc/powerdns/pdns.d/hostzit-secondary.conf", "/etc/php/", "/var/spool/hostzit/",
	"/etc/systemd/network/50-hostzit.network", "/etc/apt/sources.list.d/hostzit-php-sury.list",
	"/etc/apt/apt.conf.d/52hostzit-auto-upgrades", "/etc/apt/apt.conf.d/53hostzit-php-restart",
}

func allowedWrite(p string) bool {
	if p != filepath.ToSlash(filepath.Clean(p)) || strings.Contains(p, "..") {
		return false
	}
	for _, pre := range writablePrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// OS is the real system. Root prefixes every path (tests); Runner
// replaces program starts (tests).
type OS struct {
	Root   string
	Runner func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
	// Mounter replaces mounts (tests; nil = real syscalls on Linux).
	Mounter func(MountReq) error
}

func (o *OS) p(path string) string { return filepath.Join(o.Root, filepath.FromSlash(path)) }

// WriteFile writes to a temporary file in the same directory, sets owner
// and mode, then renames it over the target.
func (o *OS) WriteFile(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if !allowedWrite(path) {
		return fmt.Errorf("helper refuses to write %s", path)
	}
	full := o.p(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { // #nosec G301 -- parents of system folders (modes set right after)
		return err
	}
	if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	f, err := os.CreateTemp(filepath.Dir(full), ".hz-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if o.Root == "" {
		if err := f.Chown(uid, gid); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

func (o *OS) ReadFile(path string) ([]byte, error) { return os.ReadFile(o.p(path)) } // #nosec G304 -- fixed paths of the helper

func (o *OS) Remove(path string) error {
	err := os.Remove(o.p(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// RemoveAll removes a tree; only below the helper's own places and the
// homes of accounts that are being deleted (the caller checks the name).
func (o *OS) RemoveAll(path string) error {
	if !allowedWrite(path) && !strings.HasPrefix(path, "/home/") {
		return fmt.Errorf("helper refuses to remove %s", path)
	}
	return os.RemoveAll(o.p(path))
}

func (o *OS) Mkdir(path string, mode os.FileMode, uid, gid int) error {
	full := o.p(path)
	if err := os.MkdirAll(full, 0o755); err != nil { // #nosec G301 -- parents of system folders (modes set right after)
		return err
	}
	if fi, err := os.Lstat(full); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	// Owner and mode through a descriptor opened without following a
	// symlink: an account cannot swap its folder for a link in between.
	f, err := os.OpenFile(full, os.O_RDONLY|openNoFollow, 0) // #nosec G304 -- helper paths
	if err != nil {
		return err
	}
	defer f.Close()
	if o.Root != "" && runtime.GOOS == "windows" {
		return nil // tests on Windows: no Unix modes
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if o.Root == "" {
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func (o *OS) Exists(path string) bool {
	_, err := os.Lstat(o.p(path))
	return err == nil
}

func (o *OS) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	if o.Runner != nil {
		return o.Runner(ctx, stdin, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed programs, validated arguments, no shell
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=/root"}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		return out.Bytes(), fmt.Errorf("%s: %v: %s", filepath.Base(name), err, msg)
	}
	return out.Bytes(), nil
}

func (o *OS) Mount(m MountReq) error {
	if o.Mounter != nil {
		return o.Mounter(m)
	}
	return sysMount(o.p(m.Source), o.p(m.Target), m)
}

func (o *OS) Unmount(target string) error {
	if o.Mounter != nil {
		return nil
	}
	return sysUnmount(o.p(target))
}

func (o *OS) Mounted(target string) bool {
	if o.Mounter != nil {
		return false
	}
	return sysMounted(o.p(target))
}

func (o *OS) Mknod(path string, major, minor uint32) error {
	if o.Root != "" {
		return os.WriteFile(o.p(path), nil, 0o666) // #nosec G306 -- only in tests on Windows
	}
	return sysMknod(path, major, minor)
}

func (o *OS) Symlink(target, path string) error {
	full := o.p(path)
	if o.Root != "" && runtime.GOOS == "windows" {
		return os.WriteFile(full, []byte(target), 0o644) // #nosec G306 -- tests on Windows cannot make links
	}
	if cur, err := os.Readlink(full); err == nil && cur == target {
		return nil
	}
	_ = os.Remove(full)
	return os.Symlink(target, full)
}

func (o *OS) ReadDir(path string) ([]os.DirEntry, error) { return os.ReadDir(o.p(path)) }

// runToFile runs a program with its output going straight into f (large
// database dumps).
func runToFile(ctx context.Context, f *os.File, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed programs, validated arguments, no shell
	cmd.Stdout = f
	var errb bytes.Buffer
	cmd.Stderr = &errb
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=/root"}
	err := cmd.Run()
	return errb.String(), err
}
