//go:build !linux

package helper

import (
	"errors"
	"net"
)

var errLinuxOnly = errors.New("only on Linux")

func sysMount(src, dst string, m MountReq) error      { return errLinuxOnly }
func sysUnmount(dst string) error                     { return errLinuxOnly }
func sysMounted(dst string) bool                      { return false }
func sysMknod(path string, major, minor uint32) error { return errLinuxOnly }
func peerUID(c net.Conn) (int, error)                 { return -1, errLinuxOnly }
