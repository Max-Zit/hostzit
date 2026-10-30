package logfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateAndTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs", "server.log")
	w, err := Open(p, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	w.max, w.keep = 200, 2
	for i := 0; i < 30; i++ {
		fmt.Fprintf(w, "line %02d of the log\n", i)
	}
	_ = w.Close()
	if _, err := os.Stat(p + ".2"); err != nil {
		t.Fatal("not rotated")
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Fatal("kept too many files")
	}
	b, err := Tail(p, 0, 60)
	if err != nil || !strings.HasSuffix(string(b), "line 29 of the log\n") || strings.HasPrefix(string(b), "ne") {
		t.Fatalf("tail: %q %v", b, err)
	}
	all, _ := Tail(p, 2, 1<<20)
	if !bytes.Contains(all, []byte("line 29")) || bytes.Index(all, []byte("line 20")) > bytes.Index(all, []byte("line 29")) {
		t.Fatalf("older files not first: %q", all)
	}
}
