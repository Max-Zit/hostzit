//go:build !windows

package helper

import "syscall"

const openNoFollow = syscall.O_NOFOLLOW | syscall.O_DIRECTORY
