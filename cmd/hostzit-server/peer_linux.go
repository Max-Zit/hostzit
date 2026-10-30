package main

import (
	"net"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

// localPeer names the process at the other end of a local API socket
// connection: root or the EmailZit service user. Anyone else gets "".
func localPeer(c net.Conn) string {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ""
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ""
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) // #nosec G115 -- a file descriptor
	}); err != nil || cerr != nil || cred == nil {
		return ""
	}
	if cred.Uid == 0 {
		return "root"
	}
	// looked up per connection: EmailZit may be installed after HostZit
	if u, err := user.Lookup("emailzit"); err == nil && u.Uid == strconv.FormatUint(uint64(cred.Uid), 10) {
		return "emailzit"
	}
	return ""
}
