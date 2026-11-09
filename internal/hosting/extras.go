package hosting

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// SiteExtras are the small cPanel-like settings of a website: own error
// pages, folder listings and extra file types.
type SiteExtras struct {
	// ErrorPages: status code ("404") → page in the site folder ("/404.html")
	ErrorPages map[string]string `json:"error_pages,omitempty"`
	// Indexes lists the files of a folder that has no index page.
	Indexes bool `json:"indexes,omitempty"`
	// MimeTypes: file extension without dot ("webmanifest") → type
	// ("application/manifest+json").
	MimeTypes map[string]string `json:"mime_types,omitempty"`
}

// ErrorCodes are the codes a site can have its own page for.
var ErrorCodes = []int{400, 401, 403, 404, 410, 429, 500, 502, 503, 504}

var (
	errorPageRE = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)
	mimeExtRE   = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	mimeTypeRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,99}$`)
)

// noMimeExt are extensions whose type must not change: PHP files would be
// sent as source code instead of being run.
var noMimeExt = []string{"php", "php3", "php4", "php5", "php7", "php8", "phtml", "phar", "pht", "phps", "inc", "htaccess", "htpasswd", "ini"}

// Validate checks the extras.
func (x SiteExtras) Validate() error {
	if len(x.ErrorPages) > len(ErrorCodes) {
		return errors.New("too many error pages")
	}
	for code, page := range x.ErrorPages {
		c, err := strconv.Atoi(code)
		if err != nil || !slices.Contains(ErrorCodes, c) {
			return fmt.Errorf("error page: %q is not one of the codes %s", code, codeList())
		}
		if !errorPageRE.MatchString(page) || strings.Contains(page, "..") || strings.Contains(page, "//") {
			return fmt.Errorf("error page: %q must be a path in the site folder such as /404.html", page)
		}
	}
	if len(x.MimeTypes) > 50 {
		return errors.New("at most 50 file types per site")
	}
	for ext, typ := range x.MimeTypes {
		if !mimeExtRE.MatchString(ext) {
			return fmt.Errorf("file type: %q must be an extension without a dot, such as webmanifest", ext)
		}
		if slices.Contains(noMimeExt, ext) {
			return fmt.Errorf("file type: the type of .%s files cannot be changed", ext)
		}
		if !mimeTypeRE.MatchString(typ) {
			return fmt.Errorf("file type: %q is not a type such as application/json", typ)
		}
	}
	return nil
}

func codeList() string {
	s := make([]string, len(ErrorCodes))
	for i, c := range ErrorCodes {
		s[i] = strconv.Itoa(c)
	}
	return strings.Join(s, ", ")
}

// sortedKeys returns the keys of m in order (stable nginx files).
func sortedKeys(m map[string]string) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	slices.Sort(k)
	return k
}

// extrasServer writes the server-level directives (error pages, listings).
func extrasServer(w func(string, ...any), x SiteExtras) {
	for _, code := range sortedKeys(x.ErrorPages) {
		w("    error_page %s %s;\n", code, x.ErrorPages[code])
	}
	if x.Indexes {
		w("    autoindex on;\n")
	}
}

// extrasTypes writes one location per own file type; it comes after the
// rule for hidden files and before the PHP location.
func extrasTypes(w func(string, ...any), x SiteExtras) {
	for _, ext := range sortedKeys(x.MimeTypes) {
		w("    location ~* \\.%s$ {\n        types {}\n        default_type %s;\n        try_files $uri =404;\n    }\n", ext, x.MimeTypes[ext])
	}
}
