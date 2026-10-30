// Package logfile writes a log file that rotates by size (server.log,
// server.log.1 … server.log.N) and reads its newest lines.
package logfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Defaults: 10 MB per file, the current one and 4 older ones.
const (
	DefaultSize = 10 << 20
	DefaultKeep = 4
)

// Writer appends to a log file and rotates it when it gets too large.
type Writer struct {
	mu   sync.Mutex
	path string
	max  int64
	keep int
	mode os.FileMode
	f    *os.File
	size int64
}

// Open opens (or creates) the log file.
func Open(path string, mode os.FileMode) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	w := &Writer{path: path, max: DefaultSize, keep: DefaultKeep, mode: mode}
	return w, w.open()
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, w.mode) // #nosec G304 -- our own log file
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when the file would grow too large.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, errors.New("log file closed")
	}
	if w.size+int64(len(p)) > w.max && w.size > 0 {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *Writer) rotate() error {
	_ = w.f.Close()
	for i := w.keep; i >= 1; i-- {
		src := w.path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", w.path, i-1)
		}
		_ = os.Rename(src, fmt.Sprintf("%s.%d", w.path, i))
	}
	return w.open()
}

// Close closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// Tail returns up to max bytes from the end of the log, starting at a line
// boundary; with older > 0 it also reads that many rotated files first.
func Tail(path string, older int, max int64) ([]byte, error) {
	var parts [][]byte
	var total int64
	files := []string{path}
	for i := 1; i <= older; i++ {
		files = append(files, fmt.Sprintf("%s.%d", path, i))
	}
	var firstErr error
	for _, p := range files {
		if total >= max {
			break
		}
		b, err := tailFile(p, max-total)
		if err != nil {
			if p == path {
				firstErr = err
			}
			continue
		}
		parts = append([][]byte{b}, parts...)
		total += int64(len(b))
	}
	return bytes.Join(parts, nil), firstErr
}

func tailFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- our own log files
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := st.Size() - max
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, err
	}
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b, nil
}
