package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestOIDCProvider(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin()
	ctx := context.Background()
	a.ok("/settings/hosting", url.Values{"mode": {"shared"}, "server_name": {"host1.hostzit.test"}, "ipv4": {"192.0.2.10"}, "nameservers": {"ns1.hostzit.test\nns2.hostzit.test"},
		"default_php": {"8.4"}, "grace_days": {"14"}, "spf": {"v=spf1 a mx ~all"}})
	a.ok("/packages/new", url.Values{"name": {"P"}, "slug": {"p"}, "max_sites": {"3"}, "max_dbs": {"3"}, "max_zones": {"3"}, "disk_mb": {"1000"}, "inodes": {"0"},
		"cpu_percent": {"100"}, "memory_mb": {"512"}, "processes": {"50"}, "io_weight": {"100"}, "php_workers": {"2"}, "php_memory_mb": {"128"}, "upload_mb": {"16"}})
	a.ok("/customers/new", url.Values{"username": {"shop"}, "package": {"1"}, "domain": {"shop.example.com"}, "password": {"shop password 123"}, "email": {"s@example.com"}})
	cust, _ := e.st.CustomerByRef(ctx, "shop")
	const redirect = "https://mail.example.com:8444/sso/oidc/callback"

	// the client: a bad address is refused, then the secret is shown once
	if st, _, loc := a.post("/settings/emailzit/sso", url.Values{"redirect_uri": {"http://mail.example.com/cb"}}); st != http.StatusSeeOther || loc != "/settings/emailzit" {
		t.Fatalf("http redirect: %d %s", st, loc)
	}
	st0, _, loc0 := a.post("/settings/emailzit/sso", url.Values{"redirect_uri": {redirect}})
	if st0 != http.StatusSeeOther {
		t.Fatalf("client save: %d %s", st0, loc0)
	}
	page := a.page(loc0)
	secret := regexp.MustCompile(`hzc_[A-Za-z0-9_-]+`).FindString(page)
	if secret == "" {
		t.Fatal("the client secret was not shown")
	}
	if strings.Contains(a.page("/settings/emailzit"), secret) {
		t.Fatal("the client secret is shown again")
	}
	if !strings.Contains(page, "https://host1.hostzit.test:8443/.well-known/openid-configuration") {
		t.Error("issuer not shown")
	}

	// discovery
	resp, err := http.Get(e.panel.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var disc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if disc["issuer"] != "https://host1.hostzit.test:8443" || disc["token_endpoint"] != "https://host1.hostzit.test:8443/oidc/token" {
		t.Fatalf("discovery %v", disc)
	}

	verifier := "a-long-verifier-of-pkce-0123456789-0123456789-xyz"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authURL := "/oidc/authorize?" + url.Values{"response_type": {"code"}, "client_id": {"emailzit"}, "redirect_uri": {redirect}, "scope": {"openid profile email"},
		"state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}.Encode()

	c := e.client(e.panel.URL)
	// not signed in: to the sign-in first
	if st, _, loc := c.get(authURL); st != http.StatusSeeOther || !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("anonymous authorize: %d %s", st, loc)
	}
	c.ok("/login", url.Values{"username": {"shop"}, "password": {"shop password 123"}})
	// a redirect address that is not registered never gets a code
	bad := strings.Replace(authURL, url.QueryEscape(redirect), url.QueryEscape("https://evil.example/cb"), 1)
	if st, _, loc := c.get(bad); st != http.StatusBadRequest || loc != "" {
		t.Fatalf("foreign redirect: %d %s", st, loc)
	}
	// PKCE is required
	if _, _, loc := c.get(strings.Replace(authURL, "code_challenge_method=S256", "code_challenge_method=plain", 1)); !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("plain PKCE: %s", loc)
	}
	code := func() string {
		st, _, loc := c.get(authURL)
		u, _ := url.Parse(loc)
		if st != http.StatusSeeOther || !strings.HasPrefix(loc, redirect+"?") || u.Query().Get("state") != "st-1" || u.Query().Get("code") == "" {
			t.Fatalf("authorize: %d %s", st, loc)
		}
		return u.Query().Get("code")
	}
	token := func(form url.Values, user, pass string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, e.panel.URL+"/oidc/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		b, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(b, &out)
		return resp.StatusCode, out
	}
	k := code()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {k}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	if st, _ := token(form, "emailzit", "wrong"); st != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", st)
	}
	st, out := token(form, "emailzit", secret)
	if st != http.StatusOK || out["id_token"] == nil {
		t.Fatalf("token: %d %v", st, out)
	}
	// the code works once
	if st, out := token(form, "emailzit", secret); st != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("code used twice: %d %v", st, out)
	}
	// a wrong verifier fails (client_secret_post this time)
	f2 := url.Values{"grant_type": {"authorization_code"}, "code": {code()}, "redirect_uri": {redirect}, "code_verifier": {"wrong-verifier"}, "client_id": {"emailzit"}, "client_secret": {secret}}
	if st, out := token(f2, "", ""); st != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %v", st, out)
	}

	// the ID token: signed with the published key, the agreed claims
	resp, _ = http.Get(e.panel.URL + "/oidc/jwks")
	var jwks jose.JSONWebKeySet
	_ = json.NewDecoder(resp.Body).Decode(&jwks)
	resp.Body.Close()
	tok, err := jwt.ParseSigned(out["id_token"].(string), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	keys := jwks.Key(tok.Headers[0].KeyID)
	if len(keys) != 1 {
		t.Fatalf("kid %q not in the key set", tok.Headers[0].KeyID)
	}
	var std jwt.Claims
	var extra struct {
		Nonce    string   `json:"nonce"`
		Username string   `json:"username"`
		Email    string   `json:"email"`
		AMR      []string `json:"amr"`
		Locales  string   `json:"ui_locales"`
	}
	if err := tok.Claims(keys[0].Key, &std, &extra); err != nil {
		t.Fatal(err)
	}
	if std.Issuer != "https://host1.hostzit.test:8443" || std.Subject != cust.UUID || !std.Audience.Contains("emailzit") || extra.Nonce != "n-1" ||
		extra.Username != "shop" || extra.Email != "s@example.com" || len(extra.AMR) == 0 || extra.Locales == "" {
		t.Fatalf("claims %+v %+v", std, extra)
	}
	// userinfo with the access token
	req, _ := http.NewRequest(http.MethodGet, e.panel.URL+"/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+out["access_token"].(string))
	resp, _ = http.DefaultClient.Do(req)
	var ui map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&ui)
	resp.Body.Close()
	if ui["sub"] != cust.UUID || ui["username"] != "shop" {
		t.Fatalf("userinfo %v", ui)
	}
	req.Header.Set("Authorization", "Bearer nope")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo with a bad token: %d", resp.StatusCode)
	}
	// switched off: no client any more
	a.ok("/settings/emailzit/sso", url.Values{"off": {"on"}})
	if st, _, _ := c.get(authURL); st != http.StatusBadRequest {
		t.Fatalf("authorize after switching off: %d", st)
	}
}
