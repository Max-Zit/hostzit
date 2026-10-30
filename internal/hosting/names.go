// Package hosting holds what the panel and the root helper share: the rules
// for names (accounts, domains, databases, paths) and the renderers that
// turn validated values into system configuration (nginx, PHP-FPM, systemd).
//
// Everything a customer types passes through the checks here before it can
// reach a file or a command line, and the renderers check again: a value
// that would need escaping is refused, never escaped.
package hosting

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// UIDBase is the first Linux uid of hosting accounts (agreed with EmailZit,
// whose mail uids start at 2 000 000).
const UIDBase = 1_000_000

// MaxAccounts is the highest account number (uids 1 000 000–1 999 999).
const MaxAccounts = 999_999

var accountRE = regexp.MustCompile(`^[a-z][a-z0-9]{2,15}$`)

// reservedAccounts are names that would clash with system users, groups or
// paths the panel uses.
var reservedAccounts = map[string]bool{
	"root": true, "admin": true, "daemon": true, "bin": true, "sys": true, "sync": true, "games": true, "man": true, "lp": true,
	"mail": true, "news": true, "uucp": true, "proxy": true, "backup": true, "list": true, "irc": true, "nobody": true,
	"systemd": true, "messagebus": true, "sshd": true, "postgres": true, "mysql": true, "mariadb": true, "pdns": true,
	"nginx": true, "wwwdata": true, "hostzit": true, "emailzit": true, "vmail": true, "postfix": true, "dovecot": true,
	"www": true, "ftp": true, "test": true, "cpanel": true, "whm": true, "panel": true, "api": true, "acme": true,
	"cache": true, "tmp": true, "var": true, "home": true, "usr": true, "etc": true, "run": true, "dev": true, "proc": true,
	"sys0": true, "operator": true, "support": true, "staff": true, "users": true, "nogroup": true, "shadow": true,
}

// ValidAccount checks an account (Linux user) name.
func ValidAccount(name string) error {
	if !accountRE.MatchString(name) {
		return errors.New("the account name must be 3–16 characters: lowercase letters and digits, starting with a letter")
	}
	if reservedAccounts[name] {
		return fmt.Errorf("the account name %q is reserved", name)
	}
	return nil
}

// UID is the Linux uid (and gid) of account number n.
func UID(n int) (int, error) {
	if n < 1 || n > MaxAccounts {
		return 0, errors.New("account number out of range")
	}
	return UIDBase + n, nil
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var tldRE = regexp.MustCompile(`^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)

var domainProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.Transitional(false), idna.ValidateLabels(true), idna.StrictDomainName(true))

// NormalizeDomain lower-cases a domain name, converts international names
// to their xn-- form and checks it as a host name with at least two labels.
// A trailing dot is dropped. The result is safe in nginx server_name, file
// names and DNS records.
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.TrimSpace(d), ".")
	if d == "" {
		return "", errors.New("enter a domain name")
	}
	a, err := domainProfile.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid domain name", d)
	}
	a = strings.ToLower(a)
	if len(a) > 253 {
		return "", errors.New("the domain name is too long")
	}
	labels := strings.Split(a, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%q is not a full domain name (example.com)", d)
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return "", fmt.Errorf("%q is not a valid domain name", d)
		}
	}
	if !tldRE.MatchString(labels[len(labels)-1]) {
		return "", fmt.Errorf("%q does not end with a valid top-level domain", d)
	}
	return a, nil
}

// ValidDomain reports whether d is already a normalized domain name.
func ValidDomain(d string) bool {
	n, err := NormalizeDomain(d)
	return err == nil && n == d
}

// IsSubdomainOf reports whether d is parent or a name below it.
func IsSubdomainOf(d, parent string) bool {
	return d == parent || strings.HasSuffix(d, "."+parent)
}

var dbSuffixRE = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// DatabaseName builds the name of a customer database or database user:
// <account>_<suffix>, like cPanel. Only lowercase letters, digits and _.
func DatabaseName(account, suffix string) (string, error) {
	if err := ValidAccount(account); err != nil {
		return "", err
	}
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	suffix = strings.TrimPrefix(suffix, account+"_")
	if !dbSuffixRE.MatchString(suffix) {
		return "", errors.New("the name may contain lowercase letters, digits and _ (1–32 characters)")
	}
	n := account + "_" + suffix
	if len(n) > 64 {
		return "", errors.New("the name is too long")
	}
	return n, nil
}

// ValidDatabase checks a full database or database user name of an account.
func ValidDatabase(account, name string) bool {
	n, err := DatabaseName(account, strings.TrimPrefix(name, account+"_"))
	return err == nil && n == name && strings.HasPrefix(name, account+"_")
}

var pathSegRE = regexp.MustCompile(`^[A-Za-z0-9._@+-][A-Za-z0-9 ._@+,()=-]{0,254}$`)

// CleanRelPath checks a path inside an account's home ("sites/x/public",
// "backup/2026.zip"): no absolute paths, no "..", no empty or hidden
// traversal tricks, only ordinary characters. It returns the cleaned path
// with forward slashes ("" = the home itself).
func CleanRelPath(p string) (string, error) {
	p = strings.Trim(strings.ReplaceAll(p, "\\", "/"), "/")
	if p == "" || p == "." {
		return "", nil
	}
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, s := range parts {
		switch {
		case s == "" || s == ".":
			continue
		case s == "..":
			return "", errors.New("the path must stay inside the account")
		case !pathSegRE.MatchString(s):
			return "", fmt.Errorf("the name %q contains characters that are not allowed", s)
		}
		out = append(out, s)
	}
	if len(out) > 64 {
		return "", errors.New("the path is too deep")
	}
	return strings.Join(out, "/"), nil
}

// SiteDir is the folder of a site inside the account's home.
func SiteDir(domain string) string { return "sites/" + domain }

// DefaultDocRoot is the default document root of a site (relative to home).
func DefaultDocRoot(domain string) string { return SiteDir(domain) + "/public" }

// HomeDir is an account's home directory.
func HomeDir(account string) string { return "/home/" + account }

// CageDir is the root of an account's cage (private file system view).
func CageDir(account string) string { return "/var/lib/hostzit/cages/" + account }

// TmpDir is the private temporary directory of an account on the host
// (mounted as /tmp in its cage). It lives in a root-owned place, so the
// account cannot swap it for a symlink.
func TmpDir(account string) string { return "/var/lib/hostzit/tmp/" + account }

// PHPSocket is the host path of an account's PHP-FPM socket for a version.
func PHPSocket(account, version string) string {
	return CageDir(account) + "/run/php/php" + strings.ReplaceAll(version, ".", "") + ".sock"
}

var phpVersionRE = regexp.MustCompile(`^[5-9]\.[0-9]$`)

// ValidPHPVersion checks "8.3"-style versions.
func ValidPHPVersion(v string) bool { return phpVersionRE.MatchString(v) }
