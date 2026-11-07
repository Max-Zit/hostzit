package helper

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fuzz targets for what the root helper reads from sources it does not
// control: the ModSecurity audit log (request data of visitors), fail2ban
// and MariaDB output, GoAccess reports, Git addresses, restore point paths,
// transfer targets and the file manager's requests.

func FuzzWAFAudit(f *testing.F) {
	f.Add("---abc---A--\n[01/Nov/2026:10:00:00 +0100] id 198.51.100.7 1 192.0.2.1 443\n---abc---B--\nGET /?q=<script> HTTP/1.1\nHost: example.com\n---abc---H--\nModSecurity: Warning. [id \"941100\"] [msg \"XSS\"]\nModSecurity: Access denied with code 403 [id \"949110\"]\n---abc---Z--\n", "example.com")
	f.Add("---x---A--\n---x---B--\nHost: \n---x---H--\n[id \"\"]\n", "")
	f.Fuzz(func(t *testing.T, text, host string) {
		ev := parseAudit(text, []string{host, "example.com"}, 50)
		if len(ev) > 50 {
			t.Fatalf("%d events", len(ev))
		}
	})
}

func FuzzHelperOutputs(f *testing.F) {
	f.Add("198.51.100.7 \t2026-11-01 22:00:00 + 600 = 2026-11-01 22:10:00\n2001:db8::1 2026-11-01 22:00:00 + 600 = 2026-11-01 22:10:00",
		[]byte(`{"general":{"start_date":"01/Nov/2026","total_requests":5},"visitors":{"data":[{"data":"20261101","hits":{"count":5}}]}}`),
		[]byte(`<?xml version="1.0"?><resultset statement="SELECT 1"><row><field name="1">1</field><field name="x" xsi:nil="true" /></row></resultset>`))
	f.Fuzz(func(t *testing.T, bans string, goaccess, xml []byte) {
		for _, b := range parseBanIPs(bans, "ssh", time.UTC) {
			if strings.ContainsAny(b.IP, " \t\n") {
				t.Fatalf("ban %+v", b)
			}
		}
		_, _ = parseGoAccess(goaccess)
		_, _ = parseResultSets(xml)
	})
}

func FuzzRedactURL(f *testing.F) {
	f.Add("fatal: could not read from https://user:s3cr3t@github.com/a/b.git", "s3cr3t")
	f.Add("https://tok@x https://u:p@y/z", "tok")
	f.Fuzz(func(t *testing.T, s, secret string) {
		out := redactURL(s)
		if !strings.Contains(s, "@") && out != s {
			t.Fatalf("%q changed to %q", s, out)
		}
		// a token in the user part of an address never shows in the output
		if len(secret) < 6 || strings.Contains("https://…@git.example.com/r.git", secret) || strings.ContainsAny(secret, " \n\t'\"/@") || strings.Contains(s, secret) {
			return
		}
		in := s + " https://deploy:" + secret + "@git.example.com/r.git"
		if strings.Contains(redactURL(in), secret) {
			t.Fatalf("secret %q shown in %q", secret, redactURL(in))
		}
	})
}

func FuzzPaths(f *testing.F) {
	for _, s := range []string{"sites/example.com", "../x", "a/../../b", "/", "..", "a\x00b", "https://x:1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if c, err := cleanRel(p); err == nil {
			if c == ".." || strings.HasPrefix(c, "../") || strings.HasPrefix(c, "/") || strings.Contains(c, "\x00") {
				t.Fatalf("restore path %q → %q", p, c)
			}
		}
		if u, err := CheckTargetURL(p); err == nil {
			if !strings.HasPrefix(u, "https://") || strings.ContainsAny(u[8:], "/?#@ ") {
				t.Fatalf("target %q → %q", p, u)
			}
		}
		home := filepath.Join("base", "home")
		if w, err := workerPath(home, p); err == nil {
			if rel, err := filepath.Rel(home, w); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("worker path %q → %q leaves the home", p, w)
			}
		}
	})
}

// FuzzWorker runs file manager requests on a scratch home: nothing outside
// it may change.
func FuzzWorker(f *testing.F) {
	f.Add("write", "a/b.txt", "", []byte("x"), "644")
	f.Add("rename", "a", "../outside", []byte(nil), "")
	f.Add("delete", "..", "", []byte(nil), "")
	f.Add("chmod", "a", "", []byte(nil), "4777")
	f.Fuzz(func(t *testing.T, op, p, to string, data []byte, mode string) {
		root := t.TempDir()
		home := filepath.Join(root, "home")
		if err := os.MkdirAll(filepath.Join(home, "a"), 0o750); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(root, "outside")
		if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		req := `{"op":` + quote(op) + `,"path":` + quote(p) + `,"to":` + quote(to) + `,"mode":` + quote(mode) + `}`
		_ = RunWorker(home, strings.NewReader(req), &out)
		_, _ = workerDo(home, WorkerReq{Op: op, Path: p, To: to, Data: data, Mode: mode})
		ents, _ := os.ReadDir(root)
		if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" || len(ents) != 2 {
			t.Fatalf("%s %q → %q changed files outside the home", op, p, to)
		}
		if fi, err := os.Stat(home); err != nil || !fi.IsDir() {
			t.Fatalf("%s %q removed the home itself", op, p)
		}
	})
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte("0123456789abcdef"[r>>4])
			b.WriteByte("0123456789abcdef"[r&15])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
