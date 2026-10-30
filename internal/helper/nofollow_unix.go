//go:build !windows

package helper

import (
	"os"
	"syscall"
)

const openNoFollow = syscall.O_NOFOLLOW | syscall.O_DIRECTORY

const noFollowFile = syscall.O_NOFOLLOW

// fileOwner is the uid of a file.
func fileOwner(st os.FileInfo) (int, bool) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(s.Uid), true
}
