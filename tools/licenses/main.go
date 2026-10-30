// licenses writes THIRD_PARTY_LICENSES.md: every module linked into the
// given HostZit programs with its license text, read from the Go module
// cache. It fails when a license is not known to be compatible with the
// AGPL-3.0, so a new dependency is checked before a release.
//
//	go run ./tools/licenses -out THIRD_PARTY_LICENSES.md dist/hostzit-server-X-linux-amd64 dist/hostzit-agent-X-windows-amd64.exe …
package main

import (
	"bytes"
	"debug/buildinfo"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// kinds maps a phrase of the license text to its name; all are compatible
// with the AGPL-3.0.
var kinds = []struct{ phrase, name string }{
	{"Apache License", "Apache-2.0"},
	{"Mozilla Public License", "MPL-2.0"},
	{"Redistribution and use in source and binary forms", "BSD"},
	{"Permission is hereby granted, free of charge", "MIT"},
	{"Permission to use, copy, modify, and", "ISC"},
	{"public domain", "Public domain"},
}

func detect(text string) string {
	for _, k := range kinds {
		if strings.Contains(text, k.phrase) {
			if k.name == "BSD" && strings.Contains(text, "Neither the name") {
				return "BSD-3-Clause"
			}
			if k.name == "BSD" {
				return "BSD-2-Clause"
			}
			return k.name
		}
	}
	return ""
}

// licenseText finds the license file of a module directory.
func licenseText(dir string) (string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		n := strings.ToUpper(e.Name())
		if !e.IsDir() && (strings.HasPrefix(n, "LICENSE") || strings.HasPrefix(n, "LICENCE") || strings.HasPrefix(n, "COPYING")) {
			b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- module cache
			return string(b), err
		}
	}
	// Some modules state it in the README only.
	for _, name := range []string{"README.md", "README"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil { // #nosec G304 -- module cache
			return string(b), nil
		}
	}
	return "", fmt.Errorf("no license file in %s", dir)
}

func modCache() string { return goEnv("GOMODCACHE") }

func goEnv(name string) string {
	out, err := exec.Command("go", "env", name).Output() // #nosec G204 -- fixed command
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return strings.TrimSpace(string(out))
}

// escapePath applies the module cache case encoding (!x for X).
func escapePath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + 'a' - 'A')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func main() {
	out := flag.String("out", "THIRD_PARTY_LICENSES.md", "file to write")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: licenses -out FILE BINARY…")
		os.Exit(2)
	}
	mods := map[string]string{}
	goVersion := ""
	for _, bin := range flag.Args() {
		bi, err := buildinfo.ReadFile(bin)
		if err != nil {
			fmt.Fprintln(os.Stderr, bin+":", err)
			os.Exit(1)
		}
		goVersion = bi.GoVersion
		for _, d := range bi.Deps {
			if d.Replace != nil {
				d = d.Replace
			}
			mods[d.Path] = d.Version
		}
	}
	paths := make([]string, 0, len(mods))
	for p := range mods {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	cache := modCache()
	var b bytes.Buffer
	b.WriteString("# Third-party licenses\n\nHostZit is licensed under the GNU Affero General Public License v3.0 (see LICENSE).\n")
	b.WriteString("Its programs contain the following components under their own licenses, all compatible with the AGPL-3.0.\n\n")
	b.WriteString("| Component | Version | License |\n|---|---|---|\n")
	b.WriteString("| Go standard library and runtime | " + goVersion + " | BSD-3-Clause |\n")
	type entry struct{ path, version, kind, text string }
	var list []entry
	failed := false
	for _, p := range paths {
		dir := filepath.Join(cache, escapePath(p)+"@"+mods[p])
		text, err := licenseText(dir)
		kind := detect(text)
		if err != nil || kind == "" {
			fmt.Fprintf(os.Stderr, "%s %s: license not recognized (%v); check it by hand\n", p, mods[p], err)
			failed = true
			continue
		}
		list = append(list, entry{p, mods[p], kind, text})
		fmt.Fprintf(&b, "| %s | %s | %s |\n", p, mods[p], kind)
	}
	b.WriteString("\nOther components:\n\n")
	b.WriteString("- PostgreSQL (PostgreSQL License) is the database; with the development option `--dev-embedded-db` the server downloads PostgreSQL binaries (Zonky embedded-postgres-binaries, Apache-2.0) and runs them.\n")
	b.WriteString("- Some icons of the console are based on Feather Icons (MIT License, see below).\n\n")
	goroot := goEnv("GOROOT")
	if t, err := os.ReadFile(filepath.Join(goroot, "LICENSE")); err == nil { // #nosec G304 -- Go installation
		b.WriteString("## Go standard library and runtime\n\n```\n" + strings.TrimSpace(string(t)) + "\n```\n\n")
	}
	for _, e := range list {
		fmt.Fprintf(&b, "## %s %s (%s)\n\n```\n%s\n```\n\n", e.path, e.version, e.kind, strings.TrimSpace(e.text))
	}
	b.WriteString("## Feather Icons (MIT)\n\n```\n" + featherLicense + "\n```\n")
	if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil { // #nosec G306 -- a public document
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%s: %d modules\n", *out, len(list))
	if failed {
		os.Exit(1)
	}
}

// featherLicense is the license of Feather Icons (github.com/feathericons/feather),
// on which some icons of the console are based.
const featherLicense = `The MIT License (MIT)

Copyright (c) 2013-2017 Cole Bemis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`
