// i18n maintains the console catalogs (internal/web/i18n/*.json).
//
//	WZ_I18N_DUMP=$PWD/keys.json go test ./internal/web -run TestCatalogsComplete
//	go run ./tools/i18n prune   keys.json   # drop texts the console no longer uses
//	go run ./tools/i18n missing keys.json   # list texts without a translation (JSON)
//	go run ./tools/i18n merge   patch.json  # add {"de": {"English": "Deutsch"}, …}
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const dir = "internal/web/i18n"

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: i18n prune|missing|merge FILE")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p) // #nosec G304 G703 -- a file named on the command line of this developer tool
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeCatalog writes keys sorted, one per line, without HTML escaping.
func writeCatalog(p string, m map[string]string) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range keys {
		kb, vb := enc(k), enc(m[k])
		b.WriteString("  " + kb + ": " + vb)
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return os.WriteFile(p, b.Bytes(), 0o600)
}

func enc(s string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	return string(bytes.TrimRight(b.Bytes(), "\n"))
}

func run(cmd, file string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	switch cmd {
	case "prune", "missing":
		var keys []string
		if err := readJSON(file, &keys); err != nil {
			return err
		}
		used := map[string]bool{}
		for _, k := range keys {
			used[k] = true
		}
		missing := map[string]bool{}
		for _, f := range files {
			m := map[string]string{}
			if err := readJSON(f, &m); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			if cmd == "prune" {
				n := len(m)
				for k := range m {
					if !used[k] {
						delete(m, k)
					}
				}
				fmt.Printf("%s: %d → %d\n", filepath.Base(f), n, len(m))
				if err := writeCatalog(f, m); err != nil {
					return err
				}
				continue
			}
			for k := range used {
				if m[k] == "" {
					missing[k] = true
				}
			}
		}
		if cmd == "missing" {
			var out []string
			for k := range missing {
				out = append(out, k)
			}
			sort.Strings(out)
			b, _ := json.MarshalIndent(out, "", " ")
			fmt.Println(string(b))
		}
		return nil
	case "merge":
		patch := map[string]map[string]string{}
		if err := readJSON(file, &patch); err != nil {
			return err
		}
		for lang, add := range patch {
			p := filepath.Join(dir, lang+".json")
			m := map[string]string{}
			if err := readJSON(p, &m); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			for k, v := range add {
				m[k] = v
			}
			if err := writeCatalog(p, m); err != nil {
				return err
			}
			fmt.Printf("%s: +%d\n", lang, len(add))
		}
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}
