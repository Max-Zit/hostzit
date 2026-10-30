package web

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// uiTexts collects the English texts of the console: template {{.T "…"}}
// calls and the messages in the Go code that reach the page.
func uiTexts(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	tmpl := regexp.MustCompile(`\.T "((?:[^"\\]|\\.)+)"`)
	files, _ := filepath.Glob("templates/*.html")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range tmpl.FindAllStringSubmatch(string(b), -1) {
			out[unescapeText(m[1])] = true
		}
	}
	// Go: messages passed to translate/T/redirect/show*/fail and errors.
	goMsg := regexp.MustCompile(`(?:translate\([^,\n]+, |uiErrf?\(|\.T\(|fail\(|redirect\(w, r, [^\n]*?, |redirectErr\(w, r, [^,\n]+, |show\w+\(w, r, http\.Status\w+, [^"\n]*?|errors\.New\()"((?:[^"\\]|\\.)+)"`)
	for _, dir := range []string{".", "../store"} {
		gofiles, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range gofiles {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, _ := os.ReadFile(f)
			for _, m := range goMsg.FindAllStringSubmatch(string(b), -1) {
				if m[1] != "" {
					out[unescapeText(m[1])] = true
				}
			}
		}
	}
	// Composed elsewhere: password policy, device kinds, metric names.
	out["the password must be between 12 and 256 characters"] = true
	out["The name is already used."] = true
	out["Not found."] = true
	for _, s := range []string{"Active", "Suspended", "Terminated", "Administrator", "Operator", "Viewer", "Getting started", "Installing the server", "Customers and packages",
		"Websites, PHP and page cache", "Domains and DNS", "Databases", "Files, SFTP and SSH", "WordPress", "Isolation and security", "REST API for billing",
		"Users, settings and updates", "Troubleshooting and FAQ", "by hand", "before update", "before push from staging", "Company sign-in",
		"active", "suspended", "terminated", "ok", "pending", "failed", "uploaded", "queued", "running", "done", "approved", "rejected"} {
		out[s] = true
	}
	return out
}

// unescapeText turns a quoted text from the source into the text itself.
func unescapeText(s string) string { return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s) }

func TestCatalogsComplete(t *testing.T) {
	texts := uiTexts(t)
	// WZ_I18N_DUMP=file writes the list of texts (tools/i18n uses it).
	if p := os.Getenv("WZ_I18N_DUMP"); p != "" {
		keys := make([]string, 0, len(texts))
		for k := range texts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b, _ := json.MarshalIndent(keys, "", " ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	verb := regexp.MustCompile(`%[dsv]`)
	for _, l := range Languages[1:] {
		var missing []string
		for k := range texts {
			// Only Serbian must be complete; other languages fall back to English.
			if l.Code == "sr" && catalogs[l.Code][k] == "" {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s: %d texts without a translation:\n%s", l.Code, len(missing), strings.Join(missing, "\n"))
		}
		// Format verbs must survive the translation.
		for k, v := range catalogs[l.Code] {
			if strings.Join(verb.FindAllString(k, -1), "") != strings.Join(verb.FindAllString(v, -1), "") {
				t.Errorf("%s: format verbs differ: %q → %q", l.Code, k, v)
			}
		}
	}
}

func TestTemplatesParse(t *testing.T) {
	m, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) < 12 {
		t.Fatalf("only %d pages", len(m))
	}
}

func TestCatalogNoDuplicateKeys(t *testing.T) {
	raw, err := i18nFS.ReadFile("i18n/sr.json")
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if _, err := d.Token(); err != nil { // {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for d.More() {
		k, err := d.Token()
		if err != nil {
			t.Fatal(err)
		}
		if seen[k.(string)] {
			t.Errorf("duplicate key %q", k)
		}
		seen[k.(string)] = true
		if _, err := d.Token(); err != nil { // value
			t.Fatal(err)
		}
	}
}
