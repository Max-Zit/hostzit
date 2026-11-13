package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/store"
)

// HostZit as an OpenID Connect provider for its customers (customer panel):
// EmailZit (and later other MaxZit products) signs a customer in with
// "Sign in with HostZit" — one click from the hosting panel to the mail
// panel. Authorization code flow with PKCE (S256) and a client secret;
// ID tokens are signed with ES256. Claims: sub = customer UUID (the same id
// in both products), username, name, email, amr, ui_locales.
// Settings → EmailZit holds the client (id "emailzit", the secret, the
// redirect address).

const (
	settingOIDCKey    = "oidc_provider_key"    // sealed PEM of the signing key
	settingOIDCClient = "oidc_provider_client" // the EmailZit client
	oidcCodeTTL       = time.Minute
	oidcTokenTTL      = 5 * time.Minute
)

// OIDCClient is a product that signs customers in with HostZit.
type OIDCClient struct {
	ID          string `json:"id"`
	Secret      string `json:"secret"` // sealed
	RedirectURI string `json:"redirect_uri"`
}

type oidcGrant struct {
	client, redirect, challenge, nonce string
	userID                             int64
	customer                           *store.Customer
	amr                                []string
	lang                               string
	authTime, expires                  time.Time
}

type oidcState struct {
	mu     sync.Mutex
	codes  map[string]*oidcGrant // one-time codes (hashed)
	access map[string]*oidcGrant // access tokens for /oidc/userinfo (hashed)
}

var idp = &oidcState{codes: map[string]*oidcGrant{}, access: map[string]*oidcGrant{}}

func hashTok(t string) string { s := sha256.Sum256([]byte(t)); return string(s[:]) }

func (o *oidcState) put(m map[string]*oidcGrant, tok string, g *oidcGrant) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	for k, v := range m {
		if now.After(v.expires) {
			delete(m, k)
		}
	}
	m[hashTok(tok)] = g
}

// take returns a grant once (codes) or while it is valid (access tokens).
func (o *oidcState) take(m map[string]*oidcGrant, tok string, once bool) *oidcGrant {
	o.mu.Lock()
	defer o.mu.Unlock()
	g := m[hashTok(tok)]
	if once {
		delete(m, hashTok(tok))
	}
	if g == nil || time.Now().After(g.expires) {
		return nil
	}
	return g
}

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOIDCDiscovery)
		mux.HandleFunc("GET /oidc/jwks", s.handleOIDCJWKS)
		mux.HandleFunc("POST /oidc/token", s.handleOIDCToken)
		mux.HandleFunc("GET /oidc/userinfo", s.handleOIDCUserinfo)
		c("GET /oidc/authorize", s.handleOIDCAuthorize)
	})
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("POST /settings/emailzit/sso", s.handleOIDCClientSave)
	})
}

// issuer is the customer panel's public address: Settings → Hosting →
// customer panel address, else the server name with the panel port. It is
// the same on both panels (never taken from the request).
func (s *Server) issuer(ctx context.Context, _ *http.Request) string {
	hs := s.hostingSettings(ctx)
	if hs.PanelURL != "" {
		return strings.TrimRight(hs.PanelURL, "/")
	}
	port := "8443"
	if n, err := s.Network(ctx); err == nil {
		if i := strings.LastIndex(n.PanelListen, ":"); i >= 0 && n.PanelListen[i+1:] != "" {
			port = n.PanelListen[i+1:]
		}
	}
	if port == "443" {
		return "https://" + hs.ServerName
	}
	return "https://" + hs.ServerName + ":" + port
}

func (s *Server) oidcClient(ctx context.Context) OIDCClient {
	var c OIDCClient
	_ = s.store.GetSetting(ctx, settingOIDCClient, &c)
	return c
}

var oidcKeyOnce sync.Mutex

// oidcKey is the signing key, made once and stored sealed.
func (s *Server) oidcKey(ctx context.Context) (*ecdsa.PrivateKey, string, error) {
	oidcKeyOnce.Lock()
	defer oidcKeyOnce.Unlock()
	var sealed string
	if err := s.store.GetSetting(ctx, settingOIDCKey, &sealed); err == nil && sealed != "" {
		if p, err := s.store.OpenSecret("oidc.key", sealed); err == nil {
			if b, _ := pem.Decode([]byte(p)); b != nil {
				if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
					return k, keyID(&k.PublicKey), nil
				}
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, "", err
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := s.store.SetSetting(ctx, settingOIDCKey, s.store.SealSecret("oidc.key", string(p))); err != nil {
		return nil, "", err
	}
	return k, keyID(&k.PublicKey), nil
}

func keyID(pub *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:12])
}

func oidcJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, v)
}

func oidcError(w http.ResponseWriter, status int, code, desc string) {
	oidcJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	iss := s.issuer(r.Context(), r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oidc/authorize",
		"token_endpoint":                        iss + "/oidc/token",
		"userinfo_endpoint":                     iss + "/oidc/userinfo",
		"jwks_uri":                              iss + "/oidc/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "username", "name", "email", "amr", "ui_locales", "nonce", "auth_time"},
	})
}

func (s *Server) handleOIDCJWKS(w http.ResponseWriter, r *http.Request) {
	k, kid, err := s.oidcKey(r.Context())
	if err != nil {
		oidcError(w, http.StatusInternalServerError, "server_error", "no signing key")
		return
	}
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}}})
}

// handleOIDCAuthorize runs for a signed-in customer (requireUser sends
// everyone else to the sign-in first) and answers the client with a code.
func (s *Server) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cl := s.oidcClient(r.Context())
	if cl.ID == "" || q.Get("client_id") != cl.ID || q.Get("redirect_uri") != cl.RedirectURI {
		// never redirect to an address that is not registered
		http.Error(w, "unknown client or redirect address", http.StatusBadRequest)
		return
	}
	back := func(params url.Values) {
		if st := q.Get("state"); st != "" {
			params.Set("state", st)
		}
		sep := "?"
		if strings.Contains(cl.RedirectURI, "?") {
			sep = "&"
		}
		http.Redirect(w, r, cl.RedirectURI+sep+params.Encode(), http.StatusSeeOther)
	}
	if q.Get("response_type") != "code" {
		back(url.Values{"error": {"unsupported_response_type"}})
		return
	}
	if !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		back(url.Values{"error": {"invalid_scope"}, "error_description": {"scope must contain openid"}})
		return
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 {
		back(url.Values{"error": {"invalid_request"}, "error_description": {"PKCE with S256 is required"}})
		return
	}
	u := userFrom(r)
	c, err := s.store.CustomerByID(r.Context(), *u.CustomerID)
	if err != nil || c.Status != store.StatusActive {
		back(url.Values{"error": {"access_denied"}})
		return
	}
	amr := []string{"pwd"}
	if u.TOTPEnabled {
		amr = append(amr, "otp")
	}
	code := auth.RandomToken(32)
	idp.put(idp.codes, code, &oidcGrant{client: cl.ID, redirect: cl.RedirectURI, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), userID: u.ID,
		customer: c, amr: amr, lang: s.lang(r, u), authTime: time.Now(), expires: time.Now().Add(oidcCodeTTL)})
	s.audit(r, "oidc.authorize", "customer:"+c.Username, "signed in to %s", cl.ID)
	back(url.Values{"code": {code}})
}

func (s *Server) clientAuth(r *http.Request, cl OIDCClient) bool {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	want, err := s.store.OpenSecret("oidc.client", cl.Secret)
	return err == nil && cl.ID != "" && id == cl.ID && secret != "" && subtle.ConstantTimeCompare([]byte(secret), []byte(want)) == 1
}

func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oidcError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	cl := s.oidcClient(r.Context())
	if !s.clientAuth(r, cl) {
		s.guard.fail(r.Context(), clientIP(r), "", "oidc client")
		oidcError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if r.PostFormValue("grant_type") != "authorization_code" {
		oidcError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code")
		return
	}
	g := idp.take(idp.codes, r.PostFormValue("code"), true)
	if g == nil || g.client != cl.ID || g.redirect != r.PostFormValue("redirect_uri") {
		oidcError(w, http.StatusBadRequest, "invalid_grant", "the code is unknown, used or expired")
		return
	}
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(g.challenge)) != 1 {
		oidcError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	k, kid, err := s.oidcKey(r.Context())
	if err != nil {
		oidcError(w, http.StatusInternalServerError, "server_error", "no signing key")
		return
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		oidcError(w, http.StatusInternalServerError, "server_error", "signer")
		return
	}
	now := time.Now()
	claims := s.oidcClaims(g)
	std := jwt.Claims{Issuer: s.issuer(r.Context(), r), Subject: g.customer.UUID, Audience: jwt.Audience{cl.ID}, IssuedAt: jwt.NewNumericDate(now),
		Expiry: jwt.NewNumericDate(now.Add(oidcTokenTTL)), NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second))}
	extra := map[string]any{"auth_time": g.authTime.Unix(), "nonce": g.nonce}
	for k, v := range claims {
		extra[k] = v
	}
	if g.nonce == "" {
		delete(extra, "nonce")
	}
	idt, err := jwt.Signed(sig).Claims(std).Claims(extra).Serialize()
	if err != nil {
		oidcError(w, http.StatusInternalServerError, "server_error", "token")
		return
	}
	at := auth.RandomToken(32)
	ag := *g
	ag.expires = now.Add(oidcTokenTTL)
	idp.put(idp.access, at, &ag)
	oidcJSON(w, http.StatusOK, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(oidcTokenTTL.Seconds()), "id_token": idt})
}

// oidcClaims are the profile claims of a grant.
func (s *Server) oidcClaims(g *oidcGrant) map[string]any {
	c := map[string]any{"username": g.customer.Username, "amr": g.amr, "ui_locales": g.lang}
	if g.customer.DisplayName != "" {
		c["name"] = g.customer.DisplayName
	}
	if g.customer.Email != "" {
		c["email"] = g.customer.Email
	}
	return c
}

func (s *Server) handleOIDCUserinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	g := idp.take(idp.access, tok, false)
	if !ok || g == nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oidcError(w, http.StatusUnauthorized, "invalid_token", "unknown or expired token")
		return
	}
	c := s.oidcClaims(g)
	c["sub"] = g.customer.UUID
	writeJSON(w, http.StatusOK, c)
}

// handleOIDCClientSave sets up EmailZit as a client: the redirect address
// and a new secret, shown once.
func (s *Server) handleOIDCClientSave(w http.ResponseWriter, r *http.Request) {
	red := strings.TrimSpace(r.FormValue("redirect_uri"))
	if r.FormValue("off") != "" {
		_ = s.store.SetSetting(r.Context(), settingOIDCClient, OIDCClient{})
		s.cspForget()
		s.audit(r, "oidc.client", "settings", "sign-in for EmailZit switched off")
		s.redirect(w, r, "/settings/emailzit", "Saved.")
		return
	}
	p, err := url.Parse(red)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || p.Fragment != "" || len(red) > 300 {
		s.redirectErr(w, r, "/settings/emailzit", "The redirect address must be an https:// address of EmailZit.")
		return
	}
	cl := s.oidcClient(r.Context())
	cl.ID, cl.RedirectURI = "emailzit", red
	secret := ""
	if cl.Secret == "" || r.FormValue("new_secret") != "" {
		secret = "hzc_" + auth.RandomToken(32)
		cl.Secret = s.store.SealSecret("oidc.client", secret)
	}
	if err := s.store.SetSetting(r.Context(), settingOIDCClient, cl); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.cspForget()
	if _, _, err := s.oidcKey(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "oidc.client", "settings", "sign-in for EmailZit, redirect %s, new secret %t", red, secret != "")
	if secret != "" {
		s.redirect(w, r, "/settings/emailzit", translate(s.lang(r, userFrom(r)), "Saved. The client secret for EmailZit (shown only now): %s", secret))
		return
	}
	s.redirect(w, r, "/settings/emailzit", "Saved.")
}
