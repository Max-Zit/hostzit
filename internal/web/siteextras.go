package web

import (
	"errors"
	"slices"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Own error pages, folder listings and file types of a website (customer
// panel → the site → Settings).

// parsePairs reads "key value" lines into a map (both fields required).
func parsePairs(text, what string) (map[string]string, error) {
	m := map[string]string{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, errors.New(what)
		}
		m[strings.ToLower(strings.TrimPrefix(f[0], "."))] = f[1]
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// parseExtras reads the form fields of the site settings.
func parseExtras(errorPages, mimeTypes string, indexes bool) (hosting.SiteExtras, error) {
	x := hosting.SiteExtras{Indexes: indexes}
	var err error
	if x.ErrorPages, err = parsePairs(errorPages, "Error pages: one per line, the code and the page, e.g. 404 /404.html"); err != nil {
		return x, err
	}
	if x.MimeTypes, err = parsePairs(strings.ToLower(mimeTypes), "File types: one per line, the extension and the type, e.g. webmanifest application/manifest+json"); err != nil {
		return x, err
	}
	return x, x.Validate()
}

// pairsText writes a map as "key value" lines in key order.
func pairsText(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k + " " + m[k])
	}
	return b.String()
}
