package dnsprobe

import (
	"encoding/binary"
	"testing"
)

func TestParseSOA(t *testing.T) {
	q, id, err := soaQuery("example.com")
	if err != nil {
		t.Fatal(err)
	}
	m := append([]byte{}, q...)
	binary.BigEndian.PutUint16(m, id)
	m[2], m[3] = 0x84, 0x00              // answer, authoritative, NOERROR
	binary.BigEndian.PutUint16(m[6:], 1) // one answer
	rdata := []byte{3, 'n', 's', '1', 0xC0, 12, 0xC0, 12}
	rdata = binary.BigEndian.AppendUint32(rdata, 2026103001)
	rdata = append(rdata, make([]byte, 16)...) // refresh, retry, expire, minimum
	m = append(m, 0xC0, 12, 0, 6, 0, 1, 0, 0, 14, 16)
	m = binary.BigEndian.AppendUint16(m, uint16(len(rdata)))
	m = append(m, rdata...)
	serial, ok, err := parseSOA(m)
	if err != nil || !ok || serial != 2026103001 {
		t.Fatalf("serial %d ok %v err %v", serial, ok, err)
	}
	m[3] = 5 // REFUSED: the server does not have the zone
	if _, ok, err := parseSOA(m); ok || err != nil {
		t.Fatalf("refused: ok %v err %v", ok, err)
	}
	if _, _, err := parseSOA(m[:20]); err == nil {
		m[3] = 0
		if _, _, err := parseSOA(m[:20]); err == nil {
			t.Fatal("short message accepted")
		}
	}
}
