package store

import (
	"bytes"
	"testing"
)

// Database dumps come with uploaded console backups.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte("\x01\x00\x00\x00\x03abc\x02\x00\x00\x00\x00"))
	f.Add([]byte("\x01\xff\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		for i := 0; i < 64; i++ {
			_, p, err := readFrame(r)
			if err != nil {
				return
			}
			if len(p) > maxFrame {
				t.Fatalf("frame of %d bytes", len(p))
			}
		}
	})
}
