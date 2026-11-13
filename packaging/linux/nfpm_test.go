package linux

import (
	"os"
	"strings"
	"testing"
)

// Every file in the package states its mode. Without one nfpm takes the
// mode of the source file, and on Windows that is 0664: up to 0.9.4 the
// release packages had group-writable files, and Debian's logrotate refused
// /etc/logrotate.d/hostzit, so the logs of the websites were never rotated.
func TestEveryPackagedFileHasMode(t *testing.T) {
	b, err := os.ReadFile("nfpm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var entries [][]string
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		switch {
		case line == "contents:":
			in = true
		case in && line != "" && !strings.HasPrefix(line, " "):
			in = false
		case in && strings.HasPrefix(line, "  - "):
			entries = append(entries, []string{line})
		case in && len(entries) > 0:
			entries[len(entries)-1] = append(entries[len(entries)-1], line)
		}
	}
	if len(entries) < 5 {
		t.Fatalf("only %d entries read from nfpm.yaml", len(entries))
	}
	for _, e := range entries {
		dst, mode := "", ""
		for _, l := range e {
			l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "- "))
			if v, ok := strings.CutPrefix(l, "dst:"); ok {
				dst = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(l, "mode:"); ok {
				mode = strings.TrimSpace(v)
			}
		}
		switch mode {
		case "0644", "0755":
		case "":
			t.Errorf("%s: no file_info mode", dst)
		default:
			t.Errorf("%s: mode %s (want 0644 or 0755)", dst, mode)
		}
	}
}
