// labqa drives a HostZit test server through its panels like a person
// would (lab tests): first-run setup with two-factor sign-in, settings,
// packages, customers, websites, databases, page cache.
//
//	go run ./tools/labqa -admin https://10.0.0.5:8442 -panel https://10.0.0.5:8443 -creds credentials.txt setup
//	go run ./tools/labqa … customer NAME DOMAIN      (creates a customer with a website)
//	go run ./tools/labqa … api                       (makes an API token, prints nothing secret)
//
// The credentials file keeps the administrator's password and TOTP secret
// (lines "labqa-admin <password> <secret>", "labqa-customer <name> <password>").
package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
)

type client struct {
	base string
	c    *http.Client
}

func newClient(base string) *client {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- lab servers have self-signed certificates
	return &client{base: strings.TrimRight(base, "/"), c: &http.Client{Jar: jar, Transport: tr, Timeout: 5 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) do(method, path string, form url.Values) (int, string, string, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return 0, "", "", err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", c.base)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Location"), nil
}

var flashErr = regexp.MustCompile(`(?s)class="flash err" role="alert">.*?<span>(.*?)</span>`)

// post sends a form and follows one redirect; it fails when the next page
// shows an error.
func (c *client) post(path string, form url.Values) (string, error) {
	st, body, loc, err := c.do("POST", path, form)
	if err != nil {
		return "", err
	}
	if st == http.StatusSeeOther && loc != "" {
		_, body, _, err = c.do("GET", loc, nil)
		if err != nil {
			return "", err
		}
	}
	for _, m := range flashErr.FindAllStringSubmatch(body, -1) {
		if !strings.Contains(m[1], "Development mode") {
			return body, fmt.Errorf("POST %s: %s", path, m[1])
		}
	}
	if st >= 400 {
		return body, fmt.Errorf("POST %s: HTTP %d", path, st)
	}
	return body, nil
}

func readCreds(file string) map[string][]string {
	out := map[string][]string{}
	f, err := os.Open(file) // #nosec G304 -- the operator's file
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) >= 2 && strings.HasPrefix(fl[0], "labqa-") {
			key := fl[0]
			if fl[0] == "labqa-customer" {
				key += ":" + fl[1]
			}
			out[key] = fl[1:]
		}
	}
	return out
}

func appendCreds(file, line string) error {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- the operator's file
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

var secretRE = regexp.MustCompile(`<code class="secret"[^>]*>([A-Z2-7]+)</code>`)

func code(secret string) string {
	c, _ := auth.TOTPCode(secret, time.Now().Unix()/30)
	return c
}

// adminLogin signs in (and does the first-run setup when needed).
func adminLogin(a *client, creds string) error {
	cr := readCreds(creds)
	st, _, loc, err := a.do("GET", "/", nil)
	if err != nil {
		return err
	}
	if st == http.StatusSeeOther && loc == "/setup" {
		tok := os.Getenv("HZ_SETUP_TOKEN")
		pw := auth.RandomToken(18)
		if _, err := a.post("/setup", url.Values{"token": {tok}, "username": {"admin"}, "password": {pw}, "password2": {pw}}); err != nil {
			return err
		}
		_, body, _, _ := a.do("GET", "/login/enroll", nil)
		m := secretRE.FindStringSubmatch(body)
		if m == nil {
			return errors.New("no TOTP secret on the enrolment page")
		}
		if _, err := a.post("/login/enroll", url.Values{"code": {code(m[1])}}); err != nil {
			return err
		}
		if err := appendCreds(creds, "labqa-admin "+pw+" "+m[1]); err != nil {
			return err
		}
		fmt.Println("first administrator 'admin' created; password and TOTP secret saved to", creds)
		return nil
	}
	c, ok := cr["labqa-admin"]
	if !ok || len(c) < 2 {
		return errors.New("no labqa-admin line in the credentials file")
	}
	if _, err := a.post("/login", url.Values{"username": {"admin"}, "password": {c[0]}}); err != nil {
		return err
	}
	// a TOTP step can be used only once: wait for a fresh one if needed
	_, err = a.post("/login/2fa", url.Values{"code": {code(c[1])}})
	if err != nil && strings.Contains(err.Error(), "already used") {
		time.Sleep(31 * time.Second)
		if _, err = a.post("/login", url.Values{"username": {"admin"}, "password": {c[0]}}); err == nil {
			_, err = a.post("/login/2fa", url.Values{"code": {code(c[1])}})
		}
	}
	return err
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func main() {
	admin := flag.String("admin", "https://192.168.101.170:8442", "admin panel")
	panel := flag.String("panel", "https://192.168.101.170:8443", "customer panel")
	creds := flag.String("creds", "credentials.txt", "credentials file")
	ip := flag.String("ip", "192.168.101.170", "server address (DNS records)")
	php := flag.String("php", "8.4", "default PHP version (8.2 on Debian 12)")
	flag.Parse()
	a := newClient(*admin)
	must(adminLogin(a, *creds))
	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("signed in")
		return
	}
	switch args[0] {
	case "setup":
		_, err := a.post("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"hz-test.hostzit.test"}, "ipv4": {*ip}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
			"default_php": {*php}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}, "panel_url": {*panel}})
		must(err)
		_, body, _, _ := a.do("GET", "/packages", nil)
		if !strings.Contains(body, "wp-basic") {
			_, err = a.post("/packages/new", url.Values{"name": {"WordPress Basic"}, "slug": {"wp-basic"}, "max_sites": {"3"}, "max_dbs": {"3"}, "max_zones": {"3"}, "disk_mb": {"2048"},
				"inodes": {"100000"}, "cpu_percent": {"100"}, "memory_mb": {"512"}, "processes": {"60"}, "io_weight": {"100"}, "php_workers": {"4"}, "php_memory_mb": {"256"},
				"upload_mb": {"64"}, "mail_per_hour": {"100"}, "ssh": {"on"}})
			must(err)
		}
		fmt.Println("settings and package wp-basic ready")
	case "customer":
		if len(args) < 3 {
			must(errors.New("usage: customer NAME DOMAIN"))
		}
		pw := auth.RandomToken(16)
		_, err := a.post("/customers/new", url.Values{"username": {args[1]}, "package": {"1"}, "domain": {args[2]}, "dns": {"on"}, "password": {pw}, "email": {args[1] + "@example.com"}})
		must(err)
		must(appendCreds(*creds, "labqa-customer "+args[1]+" "+pw))
		fmt.Println("customer", args[1], "with", args[2], "created; password saved")
	case "passwd":
		// NAME ID: set a new panel password for a customer and save it
		pw := auth.RandomToken(16)
		_, err := a.post("/customers/"+args[2]+"/password", url.Values{"password": {pw}})
		must(err)
		must(appendCreds(*creds, "labqa-customer "+args[1]+" "+pw))
		fmt.Println("password of", args[1], "set and saved")
	case "apply":
		_, err := a.post("/customers/"+args[1]+"/apply", url.Values{})
		must(err)
		fmt.Println("customer", args[1], "set up again")
	case "site":
		// as the customer: NAME DOMAIN
		cr := readCreds(*creds)["labqa-customer:"+args[1]]
		if len(cr) < 2 {
			must(errors.New("no password for " + args[1]))
		}
		c := newClient(*panel)
		_, err := c.post("/login", url.Values{"username": {args[1]}, "password": {cr[1]}})
		must(err)
		_, err = c.post("/sites/new", url.Values{"domain": {args[2]}, "dns": {"on"}})
		must(err)
		fmt.Println("website", args[2], "created")
	case "cpage":
		cr := readCreds(*creds)["labqa-customer:"+args[1]]
		c := newClient(*panel)
		_, err := c.post("/login", url.Values{"username": {args[1]}, "password": {cr[1]}})
		must(err)
		_, body, _, err := c.do("GET", args[2], nil)
		must(err)
		fmt.Println(body)
	case "cpost":
		// as the customer: NAME PATH key=value…
		cr := readCreds(*creds)["labqa-customer:"+args[1]]
		c := newClient(*panel)
		_, err := c.post("/login", url.Values{"username": {args[1]}, "password": {cr[1]}})
		must(err)
		form := url.Values{}
		for _, kv := range args[3:] {
			k, v, _ := strings.Cut(kv, "=")
			form.Add(k, v)
		}
		_, err = c.post(args[2], form)
		must(err)
		if os.Getenv("LABQA_BODY") != "" {
			_, body, _, _ := c.do("POST", args[2], form)
			fmt.Println(body)
		}
		fmt.Println("ok")
	case "apost":
		// as the administrator: PATH key=value…
		form := url.Values{}
		for _, kv := range args[2:] {
			k, v, _ := strings.Cut(kv, "=")
			form.Add(k, v)
		}
		if out := os.Getenv("LABQA_OUT"); out != "" {
			// the answer goes into a file (it may hold a secret)
			_, body, _, err := a.do("POST", args[1], form)
			must(err)
			must(os.WriteFile(out, []byte(body), 0o600)) // #nosec G703 -- lab tool: the file the operator names
		} else {
			_, err := a.post(args[1], form)
			must(err)
		}
		fmt.Println("ok")
	case "page":
		_, body, _, err := a.do("GET", args[1], nil)
		must(err)
		fmt.Println(body)
	default:
		must(fmt.Errorf("unknown command %q", args[0]))
	}
}
