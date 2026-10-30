//go:build linux

package helper

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// sysMount bind-mounts (read-only when asked, always nosuid,nodev) or
// mounts a private proc. The target must be a directory or file the
// helper created inside a cage; the source is opened without following a
// final symlink.
func sysMount(src, dst string, m MountReq) error {
	if fi, err := os.Lstat(dst); err != nil {
		return err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("mount target %s is a symlink", dst)
	}
	if m.Proc {
		return unix.Mount("proc", dst, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "hidepid=invisible,subset=pid")
	}
	if fi, err := os.Lstat(src); err != nil {
		return err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("mount source %s is a symlink", src)
	}
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s: %w", dst, err)
	}
	// Changes below the host path must not echo through 500 cages.
	_ = unix.Mount("", dst, "", unix.MS_PRIVATE, "")
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV)
	if m.ReadOnly {
		flags |= unix.MS_RDONLY
	}
	if err := unix.Mount("", dst, "", flags, ""); err != nil {
		_ = unix.Unmount(dst, unix.MNT_DETACH)
		return fmt.Errorf("remount %s: %w", dst, err)
	}
	return nil
}

func sysUnmount(dst string) error {
	err := unix.Unmount(dst, unix.MNT_DETACH)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
		return nil // not mounted
	}
	return err
}

func sysMounted(dst string) bool {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) > 4 && unescapeMount(fl[4]) == dst {
			return true
		}
	}
	return false
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

func sysMknod(path string, major, minor uint32) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return nil
	}
	_ = os.Remove(path)
	if err := unix.Mknod(path, unix.S_IFCHR|0o666, int(unix.Mkdev(major, minor))); err != nil { // #nosec G115 -- small device numbers
		return err
	}
	return os.Chmod(path, 0o666) // #nosec G302 -- /dev/null, /dev/zero … in a cage are world-writable devices
}

// peerUID is the uid of the process on the other end of a Unix socket.
func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) // #nosec G115 -- a file descriptor
	}); err != nil {
		return -1, err
	}
	if cerr != nil {
		return -1, cerr
	}
	return int(cred.Uid), nil
}
