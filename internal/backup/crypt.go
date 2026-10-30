package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// An encrypted backup starts with encMagic, a 16-byte salt and an 8-byte
// nonce prefix. The key comes from the passphrase with scrypt. The data
// follows in chunks of at most chunkSize bytes, each sealed with AES-256-GCM:
// a 4-byte length, then the sealed chunk. The nonce is the prefix and the
// chunk number; the additional data marks the last chunk, so a cut file is
// noticed.
const (
	encMagic  = "HZENC1\n"
	chunkSize = 64 << 10
)

// ErrPassphrase is returned when the passphrase does not open a backup.
var ErrPassphrase = errors.New("the passphrase does not match this backup (or the file is damaged)")

func deriveKey(pass string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
}

type encWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix [8]byte
	n      uint32
	buf    []byte
	closed bool
}

// newEncWriter writes the header and returns a writer that seals what is
// written to it; Close writes the last chunk.
func newEncWriter(w io.Writer, pass string) (io.WriteCloser, error) {
	var salt [16]byte
	e := &encWriter{w: w, buf: make([]byte, 0, chunkSize)}
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(e.prefix[:]); err != nil {
		return nil, err
	}
	key, err := deriveKey(pass, salt[:])
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if e.aead, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, encMagic); err != nil {
		return nil, err
	}
	if _, err := w.Write(salt[:]); err != nil {
		return nil, err
	}
	if _, err := w.Write(e.prefix[:]); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *encWriter) nonce() []byte {
	var n [12]byte
	copy(n[:8], e.prefix[:])
	binary.BigEndian.PutUint32(n[8:], e.n)
	return n[:]
}

func (e *encWriter) seal(last bool) error {
	ad := []byte{0}
	if last {
		ad[0] = 1
	}
	out := e.aead.Seal(nil, e.nonce(), e.buf, ad)
	e.n++
	if e.n == 0 {
		return errors.New("backup too large")
	}
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(out))) // #nosec G115 -- at most chunkSize plus the tag
	if _, err := e.w.Write(l[:]); err != nil {
		return err
	}
	_, err := e.w.Write(out)
	e.buf = e.buf[:0]
	return err
}

func (e *encWriter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("write after close")
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), chunkSize-len(e.buf))
		e.buf = append(e.buf, p[:n]...)
		p, written = p[n:], written+n
		if len(e.buf) == chunkSize {
			if err := e.seal(false); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (e *encWriter) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.seal(true)
}

type decReader struct {
	r      io.Reader
	aead   cipher.AEAD
	prefix [8]byte
	n      uint32
	buf    []byte
	last   bool
}

// newDecReader reads the header (after encMagic) and returns a reader of
// the opened data.
func newDecReader(r io.Reader, pass string) (io.Reader, error) {
	var salt [16]byte
	d := &decReader{r: r}
	if _, err := io.ReadFull(r, salt[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, d.prefix[:]); err != nil {
		return nil, err
	}
	key, err := deriveKey(pass, salt[:])
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if d.aead, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *decReader) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		if d.last {
			return 0, io.EOF
		}
		var l [4]byte
		if _, err := io.ReadFull(d.r, l[:]); err != nil {
			return 0, errors.New("the backup file is cut off")
		}
		size := binary.BigEndian.Uint32(l[:])
		if size > chunkSize+uint32(d.aead.Overhead()) { // #nosec G115 -- small constant
			return 0, ErrPassphrase
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(d.r, sealed); err != nil {
			return 0, errors.New("the backup file is cut off")
		}
		var n [12]byte
		copy(n[:8], d.prefix[:])
		binary.BigEndian.PutUint32(n[8:], d.n)
		d.n++
		plain, err := d.aead.Open(nil, n[:], sealed, []byte{0})
		if err != nil {
			if plain, err = d.aead.Open(nil, n[:], sealed, []byte{1}); err != nil {
				return 0, ErrPassphrase
			}
			d.last = true
		}
		d.buf = plain
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

// IsEncrypted reports whether a file starting with head is an encrypted
// backup.
func IsEncrypted(head []byte) bool { return string(head) == encMagic }
