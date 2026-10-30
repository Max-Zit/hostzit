// Package dnsprobe asks name servers for the SOA serial of zones (enough to
// see whether a secondary holds the same version of a zone).
package dnsprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// SOASerial asks one name server (UDP, port 53) for the SOA serial of a
// zone. ok is false when the server answers but does not have the zone.
func SOASerial(ctx context.Context, server, zone string) (serial uint32, ok bool, err error) {
	q, id, err := soaQuery(zone)
	if err != nil {
		return 0, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return 0, false, err
	}
	defer c.Close()
	dl, _ := ctx.Deadline()
	_ = c.SetDeadline(dl)
	if _, err := c.Write(q); err != nil {
		return 0, false, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return 0, false, err
		}
		if n >= 12 && binary.BigEndian.Uint16(buf) == id {
			return parseSOA(buf[:n])
		}
	}
}

// soaQuery builds a query for the SOA record of zone (no recursion).
func soaQuery(zone string) ([]byte, uint16, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	m := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(m, id)
	binary.BigEndian.PutUint16(m[4:], 1) // one question
	for _, l := range strings.Split(strings.TrimSuffix(zone, "."), ".") {
		if l == "" || len(l) > 63 {
			return nil, 0, errors.New("invalid zone name")
		}
		m = append(m, byte(len(l)))
		m = append(m, l...)
	}
	m = append(m, 0, 0, 6, 0, 1) // root, type SOA, class IN
	return m, id, nil
}

// skipName returns the offset after a (possibly compressed) name.
func skipName(m []byte, off int) (int, error) {
	for {
		if off >= len(m) {
			return 0, errors.New("short message")
		}
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			return off + 2, nil
		case l > 63:
			return 0, errors.New("bad label")
		}
		off += 1 + l
	}
}

// parseSOA reads the serial of the first SOA record in the answer section.
func parseSOA(m []byte) (uint32, bool, error) {
	if rcode := m[3] & 0x0F; rcode != 0 {
		// REFUSED / NOTAUTH / NXDOMAIN: the server does not serve the zone
		return 0, false, nil
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if off, err = skipName(m, off); err != nil {
			return 0, false, err
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if off, err = skipName(m, off); err != nil {
			return 0, false, err
		}
		if off+10 > len(m) {
			return 0, false, errors.New("short message")
		}
		typ := binary.BigEndian.Uint16(m[off:])
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		rd := off + 10
		if rd+rdlen > len(m) {
			return 0, false, errors.New("short message")
		}
		if typ == 6 {
			p, err := skipName(m, rd) // primary name server
			if err == nil {
				p, err = skipName(m, p) // contact
			}
			if err != nil || p+4 > len(m) {
				return 0, false, errors.New("bad SOA record")
			}
			return binary.BigEndian.Uint32(m[p:]), true, nil
		}
		off = rd + rdlen
	}
	// authoritative but no SOA in the answer: not our zone there
	return 0, false, nil
}
