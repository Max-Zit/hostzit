//go:build !linux

package main

import "net"

// localPeer: the local API socket exists only on Linux.
func localPeer(net.Conn) string { return "" }
