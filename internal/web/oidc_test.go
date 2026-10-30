package web

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type fakeIdP struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	nonce string
	email string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{}
	f.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		claims := map[string]any{"iss": f.srv.URL, "aud": "hostzit", "sub": "u1", "email": f.email, "email_verified": true, "nonce": f.nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
		f.mu.Unlock()
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		b, _ := json.Marshal(claims)
		obj, _ := sig.Sign(b)
		tok, _ := obj.CompactSerialize()
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": tok, "expires_in": 300})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestCompanySignIn(t *testing.T) {
	e := newEnv(t)
	f := newFakeIdP(t)
	a := e.setupAdmin()
	u, _ := e.st.CheckPassword(t.Context(), "root1", "correct horse battery")
	a.ok("/users/"+itoa(u.ID), url.Values{"display_name": {"Root"}, "email": {"boss@corp.test"}, "role": {"admin"}})
	a.ok("/settings/signin", url.Values{"issuer": {strings.Replace(f.srv.URL, "http://127.0.0.1", "http://127.0.0.1", 1)}, "client_id": {"hostzit"}, "client_secret": {"s"}, "label": {"Corp"}, "trust_mfa": {"on"}})
	signIn := func(email string) (*client, string) {
		c := e.client(e.admin.URL)
		if !strings.Contains(c.page("/login"), "Corp") {
			t.Fatal("no company sign-in button")
		}
		_, _, loc := c.get("/login/oidc")
		lu, err := url.Parse(loc)
		if err != nil || !strings.HasPrefix(loc, f.srv.URL+"/auth") || lu.Query().Get("code_challenge") == "" {
			t.Fatalf("start went to %q", loc)
		}
		f.mu.Lock()
		f.nonce, f.email = lu.Query().Get("nonce"), email
		f.mu.Unlock()
		_, _, loc = c.get("/login/oidc/callback?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=abc")
		return c, loc
	}
	c, loc := signIn("boss@corp.test")
	if loc != "/" {
		t.Fatalf("callback went to %q", loc)
	}
	c.page("/customers")
	_, loc = signIn("stranger@corp.test")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatal("an unknown address signed in")
	}
	// a forged state is refused
	c2 := e.client(e.admin.URL)
	_, _, _ = c2.get("/login/oidc")
	if _, _, loc := c2.get("/login/oidc/callback?state=forged&code=abc"); !strings.HasPrefix(loc, "/login") {
		t.Fatal("forged state accepted")
	}
}
