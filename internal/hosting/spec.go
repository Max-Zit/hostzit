package hosting

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Limits are the resource limits of an account (from its package). Zero
// means "no limit" where noted.
type Limits struct {
	DiskMB      int  `json:"disk_mb"`       // disk quota (0 = none)
	Inodes      int  `json:"inodes"`        // file count quota (0 = none)
	CPUPercent  int  `json:"cpu_percent"`   // 100 = one core (0 = none)
	MemoryMB    int  `json:"memory_mb"`     // hard limit for all processes (0 = none)
	IOWeight    int  `json:"io_weight"`     // 1–10000, systemd default 100
	IOMBps      int  `json:"io_mbps"`       // disk read and write speed in MB/s each (0 = none)
	RedisMB     int  `json:"redis_mb"`      // memory of the account's Redis (0 = no Redis)
	Processes   int  `json:"processes"`     // TasksMax (0 = none)
	PHPWorkers  int  `json:"php_workers"`   // pm.max_children per PHP version
	PHPMemoryMB int  `json:"php_memory_mb"` // memory_limit of one PHP request
	UploadMB    int  `json:"upload_mb"`     // upload_max_filesize / client_max_body_size
	AllowExec   bool `json:"allow_exec"`    // PHP may start programs (exec, proc_open …)
	SSH         bool `json:"ssh"`           // shell access (SFTP is always allowed)
	MailPerHour int  `json:"mail_per_hour"` // mails from websites per hour (0 = none allowed)
}

// DedicatedLimits are used on a dedicated server: no sharing, so only
// sensible PHP values remain.
func DedicatedLimits() Limits {
	return Limits{IOWeight: 100, RedisMB: 256, PHPWorkers: 32, PHPMemoryMB: 512, UploadMB: 256, AllowExec: true, SSH: true, MailPerHour: 1000}
}

// Validate checks the ranges.
func (l Limits) Validate() error {
	switch {
	case l.DiskMB < 0 || l.DiskMB > 16<<20:
		return errors.New("disk space: 0–16 TB in MB")
	case l.Inodes < 0 || l.Inodes > 100_000_000:
		return errors.New("files: 0–100 000 000")
	case l.CPUPercent < 0 || l.CPUPercent > 6400:
		return errors.New("CPU: 0–6400 % (100 % = one core)")
	case l.MemoryMB != 0 && (l.MemoryMB < 128 || l.MemoryMB > 1<<20):
		return errors.New("memory: 128 MB–1 TB, or 0 for no limit")
	case l.IOWeight != 0 && (l.IOWeight < 1 || l.IOWeight > 10000):
		return errors.New("disk priority: 1–10000")
	case l.IOMBps < 0 || l.IOMBps > 100000:
		return errors.New("disk speed: 0–100000 MB/s")
	case l.RedisMB < 0 || l.RedisMB > 65536:
		return errors.New("Redis memory: 0–65536 MB")
	case l.Processes != 0 && (l.Processes < 20 || l.Processes > 100000):
		return errors.New("processes: 20–100000, or 0 for no limit")
	case l.PHPWorkers < 1 || l.PHPWorkers > 512:
		return errors.New("PHP workers: 1–512")
	case l.PHPMemoryMB < 32 || l.PHPMemoryMB > 8192:
		return errors.New("PHP memory per request: 32–8192 MB")
	case l.UploadMB < 1 || l.UploadMB > 10240:
		return errors.New("upload size: 1–10240 MB")
	case l.MailPerHour < 0 || l.MailPerHour > 100000:
		return errors.New("mails per hour: 0–100000")
	}
	return nil
}

// Account is what the helper needs to set up an account.
type Account struct {
	Name      string `json:"name"`
	Number    int    `json:"number"` // uid = UIDBase + Number
	Suspended bool   `json:"suspended"`
	Limits    Limits `json:"limits"`
	// PHPVersions the account uses (one FPM master per version).
	PHPVersions []string `json:"php_versions"`
	// Sendmail replaces HostZit's own sendmail (EmailZit installs one).
	Sendmail string `json:"sendmail,omitempty"`
	// PHP are the account's own PHP options per version.
	PHP map[string]PHPOptions `json:"php,omitempty"`
	// Redis: the customer switched the account's Redis on (needs RedisMB).
	Redis bool `json:"redis,omitempty"`
}

// Validate checks the account.
func (a Account) Validate() error {
	if err := ValidAccount(a.Name); err != nil {
		return err
	}
	if _, err := UID(a.Number); err != nil {
		return err
	}
	if err := a.Limits.Validate(); err != nil {
		return err
	}
	for v, o := range a.PHP {
		if !ValidPHPVersion(v) {
			return fmt.Errorf("invalid PHP version %q", v)
		}
		if err := o.Validate(a.Limits); err != nil {
			return fmt.Errorf("PHP %s: %w", v, err)
		}
	}
	for _, v := range a.PHPVersions {
		if !ValidPHPVersion(v) {
			return fmt.Errorf("invalid PHP version %q", v)
		}
	}
	return nil
}

// Redirect is a rule of a site.
type Redirect struct {
	From string `json:"from"` // path prefix, e.g. /old
	To   string `json:"to"`   // absolute URL or path
	Code int    `json:"code"` // 301 or 302
}

// Site is one website: a domain (+ aliases) served from a folder of the
// account.
type Site struct {
	ID         int64    `json:"id"`
	Account    string   `json:"account"`
	Domain     string   `json:"domain"`
	Aliases    []string `json:"aliases"`
	DocRoot    string   `json:"doc_root"` // relative to the home
	PHPVersion string   `json:"php_version"`
	// WWW also serves www.<domain> (and redirects it, see Canonical).
	WWW bool `json:"www"`
	// Canonical is "", "www" or "bare": redirect the other form to it.
	Canonical string `json:"canonical"`
	// TLS: a certificate is installed for the site.
	TLS        bool `json:"tls"`
	ForceHTTPS bool `json:"force_https"`
	HSTS       bool `json:"hsts"`
	// Cache is the page cache (nginx FastCGI cache).
	Cache        bool `json:"cache"`
	CacheMinutes int  `json:"cache_minutes"`
	// WordPress adds the WordPress rules (protects wp-config, uploads …).
	WordPress   bool       `json:"wordpress"`
	BlockXMLRPC bool       `json:"block_xmlrpc"`
	Redirects   []Redirect `json:"redirects"`
	Suspended   bool       `json:"suspended"`
	UploadMB    int        `json:"upload_mb"`
	// IPAllow: only these networks may open the site (empty = everyone);
	// IPDeny: these may not.
	IPAllow []string `json:"ip_allow,omitempty"`
	IPDeny  []string `json:"ip_deny,omitempty"`
	// Hotlink: images only for pages of the site itself.
	Hotlink bool `json:"hotlink,omitempty"`
	// WAF: ModSecurity with the OWASP Core Rule Set.
	WAF bool `json:"waf,omitempty"`
	// Protected folders need a user name and password.
	Protected []Protected `json:"protected,omitempty"`
}

// Names lists every host name of the site.
func (s Site) Names() []string {
	n := []string{s.Domain}
	if s.WWW {
		n = append(n, "www."+s.Domain)
	}
	n = append(n, s.Aliases...)
	return n
}

var redirectPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/%-]{0,200}$`)
var redirectURLRE = regexp.MustCompile(`^(https?://[a-z0-9.-]{1,253}(:[0-9]{1,5})?)?/[A-Za-z0-9._~/%?&=+#-]{0,500}$`)

// Validate checks the site; the renderers call it again.
func (s Site) Validate() error {
	if err := ValidAccount(s.Account); err != nil {
		return err
	}
	if s.ID <= 0 {
		return errors.New("site id missing")
	}
	if !ValidDomain(s.Domain) {
		return fmt.Errorf("invalid domain %q", s.Domain)
	}
	seen := map[string]bool{s.Domain: true}
	if s.WWW {
		seen["www."+s.Domain] = true
	}
	if len(s.Aliases) > 50 {
		return errors.New("at most 50 aliases per site")
	}
	for _, a := range s.Aliases {
		if !ValidDomain(a) {
			return fmt.Errorf("invalid alias %q", a)
		}
		if seen[a] {
			return fmt.Errorf("the name %s is listed twice", a)
		}
		seen[a] = true
	}
	if p, err := CleanRelPath(s.DocRoot); err != nil || p != s.DocRoot || p == "" || !strings.HasPrefix(p, "sites/") {
		return errors.New("the document root must be a folder inside sites/")
	}
	if !ValidPHPVersion(s.PHPVersion) {
		return fmt.Errorf("invalid PHP version %q", s.PHPVersion)
	}
	switch s.Canonical {
	case "", "bare":
	case "www":
		if !s.WWW {
			return errors.New("www as main address needs the www name")
		}
	default:
		return errors.New("invalid main address")
	}
	if s.Cache && (s.CacheMinutes < 1 || s.CacheMinutes > 1440) {
		return errors.New("the page cache lifetime must be 1–1440 minutes")
	}
	if s.UploadMB < 1 || s.UploadMB > 10240 {
		return errors.New("upload size: 1–10240 MB")
	}
	if err := s.validateAccess(); err != nil {
		return err
	}
	if len(s.Redirects) > 100 {
		return errors.New("at most 100 redirects per site")
	}
	for _, r := range s.Redirects {
		if !redirectPathRE.MatchString(r.From) || strings.Contains(r.From, "..") {
			return fmt.Errorf("redirect: %q must be a path such as /old-page", r.From)
		}
		if !redirectURLRE.MatchString(r.To) {
			return fmt.Errorf("redirect: %q must be a path or an http(s) address", r.To)
		}
		if r.Code != 301 && r.Code != 302 {
			return errors.New("redirect: the code must be 301 or 302")
		}
	}
	return nil
}

// Protected is a folder of a site behind a password (HTTP basic auth).
type Protected struct {
	Path  string   `json:"path"` // URL path, e.g. /private
	Users []HTUser `json:"users"`
}

// HTUser is a user of a protected folder; Hash is bcrypt.
type HTUser struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

var htUserRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
var bcryptRE = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

// CleanNets checks a list of IP addresses or networks for allow/deny rules.
func CleanNets(list []string) ([]string, error) {
	var out []string
	for _, x := range list {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if p, err := netip.ParsePrefix(x); err == nil {
			out = append(out, p.Masked().String())
			continue
		}
		a, err := netip.ParseAddr(x)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or network", x)
		}
		out = append(out, a.String())
	}
	if len(out) > 200 {
		return nil, errors.New("at most 200 addresses")
	}
	return out, nil
}

func (s Site) validateAccess() error {
	for _, l := range [][]string{s.IPAllow, s.IPDeny} {
		c, err := CleanNets(l)
		if err != nil {
			return err
		}
		if len(c) != len(l) {
			return errors.New("invalid address list")
		}
		for i := range c {
			if c[i] != l[i] {
				return errors.New("invalid address " + l[i])
			}
		}
	}
	if len(s.Protected) > 20 {
		return errors.New("at most 20 protected folders per site")
	}
	seen := map[string]bool{}
	for _, p := range s.Protected {
		if !redirectPathRE.MatchString(p.Path) || strings.Contains(p.Path, "..") || p.Path == "/" || strings.HasSuffix(p.Path, "/") || seen[p.Path] {
			return fmt.Errorf("protected folder: %q must be a path such as /private", p.Path)
		}
		seen[p.Path] = true
		if len(p.Users) == 0 || len(p.Users) > 50 {
			return errors.New("a protected folder needs 1–50 users")
		}
		for _, u := range p.Users {
			if !htUserRE.MatchString(u.Name) || !bcryptRE.MatchString(u.Hash) {
				return errors.New("protected folder: invalid user")
			}
		}
	}
	return nil
}

// Htpasswd renders the password file of a protected folder.
func Htpasswd(p Protected) string {
	var b strings.Builder
	for _, u := range p.Users {
		b.WriteString(u.Name + ":" + u.Hash + "\n")
	}
	return b.String()
}
