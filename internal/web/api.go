package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// The REST API follows the conventions agreed with EmailZit (INTEGRATION.md
// P4): /api/v1, JSON with snake_case, RFC 3339 times, Bearer tokens with
// scopes, errors as {"error":{"code","message","field"}}, cursor pages,
// Idempotency-Key on creating POSTs, 202 + job for slow work.

type ctxAPIKey struct{}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

type apiErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]apiErr{"error": {Code: code, Message: msg}})
}

func apiFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, store.ErrConflict):
		apiError(w, http.StatusConflict, "conflict", "already exists")
	default:
		apiError(w, http.StatusBadRequest, "invalid", storeErr(err))
	}
}

func (s *Server) apiHandler() http.Handler {
	mux := http.NewServeMux()
	need := func(scope string, pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.apiAuth(scope, h)) }
	mux.HandleFunc("GET /api/v1/zit/info", s.apiInfo)
	need("customers:read", "GET /api/v1/server/status", s.apiStatus)
	need("customers:read", "GET /api/v1/packages", s.apiPackages)
	need("customers:read", "GET /api/v1/customers", s.apiCustomers)
	need("customers:write", "POST /api/v1/customers", s.idempotent(s.apiCustomerCreate))
	need("customers:read", "GET /api/v1/customers/{id}", s.apiCustomer)
	need("customers:write", "PATCH /api/v1/customers/{id}", s.apiCustomerPatch)
	need("customers:write", "PUT /api/v1/customers/{id}/package", s.apiCustomerPackage)
	need("customers:write", "POST /api/v1/customers/{id}/suspend", s.apiCustomerStatus(store.StatusSuspended))
	need("customers:write", "POST /api/v1/customers/{id}/unsuspend", s.apiCustomerStatus(store.StatusActive))
	need("customers:write", "POST /api/v1/customers/{id}/terminate", s.apiCustomerStatus(store.StatusTerminated))
	need("usage:read", "GET /api/v1/customers/{id}/usage", s.apiUsage)
	need("sso:create", "POST /api/v1/customers/{id}/sso", s.apiSSO)
	need("customers:read", "GET /api/v1/jobs/{id}", s.apiJob)
	need("dns:mail", "GET /api/v1/domains/{domain}", s.apiDomain)
	need("dns:mail", "GET /api/v1/dns/zones/{zone}/owned/{owner}", s.apiOwned)
	need("dns:mail", "PUT /api/v1/dns/zones/{zone}/owned/{owner}", s.apiOwnedPut)
	need("dns:mail", "DELETE /api/v1/dns/zones/{zone}/owned/{owner}", s.apiOwnedPut)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "unknown API path")
	})
	return mux
}

// apiAuth checks the token, its scope, its address list and the user.
func (s *Server) apiAuth(scope string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
			apiError(w, http.StatusTooManyRequests, "rate_limited", "too many failed attempts from this address")
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			apiError(w, http.StatusUnauthorized, "unauthorized", "send an API token: Authorization: Bearer hzt_…")
			return
		}
		u, t, err := s.store.UserByAPIToken(r.Context(), strings.TrimSpace(tok), ip)
		if errors.Is(err, store.ErrBadToken) {
			s.guard.fail(r.Context(), ip, "", "API token")
			apiError(w, http.StatusUnauthorized, "unauthorized", "invalid API token")
			return
		}
		if err != nil {
			s.log.Error("API sign-in", "err", err)
			apiError(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		if !u.IsStaff() || !t.HasScope(scope) || (strings.HasSuffix(scope, ":write") || scope == "sso:create") && !u.CanWrite() {
			apiError(w, http.StatusForbidden, "forbidden", "this token may not "+scope)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		ctx = context.WithValue(ctx, ctxAPIKey{}, t)
		next(w, r.WithContext(ctx))
	})
}

func apiToken(r *http.Request) *store.APIToken {
	t, _ := r.Context().Value(ctxAPIKey{}).(*store.APIToken)
	return t
}

// ctxLocalPeer marks requests from the local API socket (the listener has
// checked the peer's uid with SO_PEERCRED); the value is the peer's name.
type ctxLocalPeer struct{}

// WithLocalPeer marks a connection of the local API socket.
func WithLocalPeer(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxLocalPeer{}, name)
}

// LocalAPIHandler serves the local socket /run/hostzit-api/api.sock: for
// EmailZit on the same server the DNS part of the API (scope dns:mail)
// without a token. Requests without a checked peer are refused.
func (s *Server) LocalAPIHandler() http.Handler {
	mux := http.NewServeMux()
	local := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := r.Context().Value(ctxLocalPeer{}).(string); !ok {
				apiError(w, http.StatusForbidden, "forbidden", "not a checked local peer")
				return
			}
			h(w, r)
		}))
	}
	local("GET /api/v1/zit/info", s.apiInfo)
	local("GET /api/v1/domains/{domain}", s.apiDomain)
	local("GET /api/v1/dns/zones/{zone}/owned/{owner}", s.apiOwned)
	local("PUT /api/v1/dns/zones/{zone}/owned/{owner}", s.apiOwnedPut)
	local("DELETE /api/v1/dns/zones/{zone}/owned/{owner}", s.apiOwnedPut)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "the local socket serves only the DNS API (dns:mail)")
	})
	return mux
}

func apiActor(r *http.Request) string {
	if p, ok := r.Context().Value(ctxLocalPeer{}).(string); ok {
		return p + " (local API socket)"
	}
	name := "-"
	if u := userFrom(r); u != nil {
		name = u.Username
	}
	if t := apiToken(r); t != nil {
		name += " (API token " + t.Name + ")"
	}
	return name
}

func (s *Server) apiAudit(r *http.Request, action, target, format string, args ...any) {
	s.auditAs(r, apiActor(r), action, target, format, args...)
}

// recorder keeps an answer for the idempotency store.
type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (rc *recorder) WriteHeader(code int) { rc.status = code; rc.ResponseWriter.WriteHeader(code) }
func (rc *recorder) Write(b []byte) (int, error) {
	rc.buf.Write(b)
	return rc.ResponseWriter.Write(b)
}

// idempotent answers a repeated request with the same Idempotency-Key
// (per token, 24 h) with the stored answer instead of doing it twice.
func (s *Server) idempotent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		t := apiToken(r)
		if key == "" || t == nil {
			next(w, r)
			return
		}
		if len(key) > 200 {
			apiError(w, http.StatusBadRequest, "invalid", "Idempotency-Key is too long")
			return
		}
		if st, body, ok := s.store.IdempotentResponse(r.Context(), t.ID, key); ok {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(st)
			_, _ = w.Write(body) // #nosec G705 -- a stored JSON answer of this API, served as application/json
			return
		}
		rc := &recorder{ResponseWriter: w, status: 200}
		next(rc, r)
		if rc.status < 500 {
			s.store.SaveIdempotent(r.Context(), t.ID, key, rc.status, rc.buf.Bytes())
		}
	}
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON: " + err.Error())
	}
	return nil
}

func (s *Server) apiInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"product": "hostzit", "version": s.Version, "panel_url": s.hostingSettings(r.Context()).PanelURL})
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	counts, err := s.store.CustomerCounts(r.Context())
	if err != nil {
		apiFail(w, err)
		return
	}
	out := map[string]any{"version": s.Version, "customers": counts, "mode": s.hostingSettings(r.Context()).Mode}
	if in, err := s.serverInfo(r.Context()); err == nil {
		out["services"], out["php_versions"], out["quota"], out["disks"], out["load"] = in.Services, in.PHPVersions, in.Quota, in.Disks, in.Load
		out["memory"] = map[string]int64{"total_mb": in.MemTotalMB, "available_mb": in.MemAvailMB}
	} else {
		out["helper_error"] = storeErr(err)
	}
	writeJSON(w, http.StatusOK, out)
}

type apiPackage struct {
	Slug      string         `json:"slug"`
	Name      string         `json:"name"`
	Limits    hosting.Limits `json:"limits"`
	MaxSites  int            `json:"max_sites"`
	MaxDBs    int            `json:"max_databases"`
	MaxZones  int            `json:"max_dns_zones"`
	Customers int            `json:"customers"`
}

func (s *Server) apiPackages(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Packages(r.Context())
	if err != nil {
		apiFail(w, err)
		return
	}
	out := []apiPackage{}
	for _, p := range list {
		out = append(out, apiPackage{Slug: p.Slug, Name: p.Name, Limits: p.Limits, MaxSites: p.MaxSites, MaxDBs: p.MaxDBs, MaxZones: p.MaxZones, Customers: p.Customers})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

type apiCustomerJSON struct {
	ID            string     `json:"id"`
	ExternalID    *string    `json:"external_id"`
	Username      string     `json:"username"`
	Number        int        `json:"number"`
	Package       string     `json:"package"`
	Status        string     `json:"status"`
	SuspendReason string     `json:"suspend_reason,omitempty"`
	Name          string     `json:"name"`
	Email         string     `json:"email"`
	Sites         int        `json:"sites"`
	Ready         bool       `json:"ready"`
	Error         string     `json:"error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	TerminatedAt  *time.Time `json:"terminated_at,omitempty"`
	DeleteAfter   *time.Time `json:"delete_after,omitempty"`
}

func toAPICustomer(c *store.Customer) apiCustomerJSON {
	return apiCustomerJSON{ID: c.UUID, ExternalID: c.ExternalID, Username: c.Username, Number: c.Number, Package: c.PackageSlug, Status: c.Status, SuspendReason: c.SuspendReason,
		Name: c.DisplayName, Email: c.Email, Sites: c.Sites, Ready: c.Applied, Error: c.ApplyError, CreatedAt: c.CreatedAt.UTC(), TerminatedAt: c.TerminatedAt, DeleteAfter: c.DeleteAfter}
}

func (s *Server) apiCustomers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.FormValue("limit"))
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 500)
	after, _ := strconv.ParseInt(r.FormValue("cursor"), 10, 64)
	list, err := s.store.Customers(r.Context(), store.CustomerFilter{AfterID: after, Limit: limit + 1, Status: r.FormValue("status"), Query: r.FormValue("q")})
	if err != nil {
		apiFail(w, err)
		return
	}
	out := map[string]any{"items": []apiCustomerJSON{}}
	items := []apiCustomerJSON{}
	for i, c := range list {
		if i == limit {
			out["next_cursor"] = strconv.FormatInt(list[i-1].ID, 10)
			break
		}
		items = append(items, toAPICustomer(c))
	}
	out["items"] = items
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiLoad(w http.ResponseWriter, r *http.Request) *store.Customer {
	c, err := s.store.CustomerByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, http.StatusNotFound, "customer_not_found", "no such customer")
		return nil
	}
	return c
}

func (s *Server) apiCustomer(w http.ResponseWriter, r *http.Request) {
	if c := s.apiLoad(w, r); c != nil {
		writeJSON(w, http.StatusOK, toAPICustomer(c))
	}
}

type apiCreate struct {
	ID         string `json:"id"` // customer UUID (optional)
	ExternalID string `json:"external_id"`
	Username   string `json:"username"`
	Package    string `json:"package"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Domain     string `json:"domain"`
	DNS        *bool  `json:"dns"`
	PHPVersion string `json:"php_version"`
}

func (s *Server) apiCustomerCreate(w http.ResponseWriter, r *http.Request) {
	var in apiCreate
	if err := readJSON(r, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	p, err := s.store.PackageBySlug(r.Context(), in.Package)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]apiErr{"error": {Code: "invalid", Message: "unknown package", Field: "package"}})
		return
	}
	if err := hosting.ValidAccount(in.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]apiErr{"error": {Code: "invalid", Message: err.Error(), Field: "username"}})
		return
	}
	if in.Domain != "" {
		if _, err := hosting.NormalizeDomain(in.Domain); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]apiErr{"error": {Code: "invalid", Message: err.Error(), Field: "domain"}})
			return
		}
	}
	if in.ID != "" {
		if _, err := s.store.CustomerByRef(r.Context(), in.ID); err == nil {
			apiError(w, http.StatusConflict, "conflict", "a customer with this id exists")
			return
		}
	}
	dns := in.DNS == nil || *in.DNS
	n := NewAccount{NewCustomer: store.NewCustomer{UUID: in.ID, ExternalID: in.ExternalID, Username: in.Username, PackageID: p.ID, DisplayName: in.Name, Email: in.Email,
		Password: in.Password, PHPVersion: in.PHPVersion}, Domain: in.Domain, DNS: dns}
	if n.UUID == "" {
		n.UUID = store.NewUUID()
	}
	// Quick checks now, so the portal gets a 400 instead of a failed job.
	if _, err := store.CleanEmail(in.Email); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]apiErr{"error": {Code: "invalid", Message: err.Error(), Field: "email"}})
		return
	}
	if _, err := s.store.CustomerByRef(r.Context(), in.Username); err == nil {
		writeJSON(w, http.StatusConflict, map[string]apiErr{"error": {Code: "conflict", Message: "the username is taken", Field: "username"}})
		return
	}
	by := apiActor(r)
	j, err := s.runJob("customer.create", nil, in.Username, func(ctx context.Context) error {
		_, err := s.createAccount(ctx, by, n)
		if err == nil {
			_ = s.store.Audit(ctx, by, "api", "customer.create", "customer:"+in.Username, "package "+p.Slug+", domain "+in.Domain)
		}
		return err
	})
	if err != nil {
		apiFail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.ID, "customer_id": n.UUID, "status": j.Status})
}

func (s *Server) apiCustomerPatch(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoad(w, r)
	if c == nil {
		return
	}
	var in struct {
		Name     *string `json:"name"`
		Email    *string `json:"email"`
		Password *string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if in.Name != nil {
		c.DisplayName = *in.Name
	}
	if in.Email != nil {
		c.Email = *in.Email
	}
	if err := s.store.UpdateCustomer(r.Context(), c); err != nil {
		apiFail(w, err)
		return
	}
	if in.Password != nil {
		if err := s.store.SetPassword(r.Context(), c.UserID, *in.Password, false, ""); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]apiErr{"error": {Code: "invalid", Message: storeErr(err), Field: "password"}})
			return
		}
	}
	s.apiAudit(r, "customer.update", "customer:"+c.Username, "contact data changed (password: %v)", in.Password != nil)
	c, _ = s.store.CustomerByID(r.Context(), c.ID)
	writeJSON(w, http.StatusOK, toAPICustomer(c))
}

func (s *Server) apiCustomerPackage(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoad(w, r)
	if c == nil {
		return
	}
	var in struct {
		Package string `json:"package"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	p, err := s.store.PackageBySlug(r.Context(), in.Package)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]apiErr{"error": {Code: "invalid", Message: "unknown package", Field: "package"}})
		return
	}
	old := c.PackageSlug
	c.PackageID = p.ID
	if err := s.store.UpdateCustomer(r.Context(), c); err != nil {
		apiFail(w, err)
		return
	}
	c, _ = s.store.CustomerByID(r.Context(), c.ID)
	if err := s.applyCustomer(r.Context(), apiActor(r), c); err != nil {
		apiError(w, http.StatusBadGateway, "internal", storeErr(err))
		return
	}
	s.apiAudit(r, "customer.package", "customer:"+c.Username, "%s → %s", old, p.Slug)
	writeJSON(w, http.StatusOK, toAPICustomer(c))
}

func (s *Server) apiCustomerStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := s.apiLoad(w, r)
		if c == nil {
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		if r.ContentLength > 0 {
			if err := readJSON(r, &in); err != nil {
				apiError(w, http.StatusBadRequest, "invalid", err.Error())
				return
			}
		}
		if status == store.StatusSuspended && in.Reason == "" {
			in.Reason = "billing"
		}
		if c.Status == store.StatusTerminated && status != store.StatusTerminated {
			apiError(w, http.StatusConflict, "conflict", "the customer is terminated")
			return
		}
		by := apiActor(r)
		j, err := s.runJob("customer."+status, &c.ID, c.Username, func(ctx context.Context) error {
			err := s.setStatus(ctx, by, c, status, in.Reason)
			_ = s.store.Audit(ctx, by, "api", "customer.status", "customer:"+c.Username, c.Status+" → "+status+" ("+in.Reason+")")
			return err
		})
		if err != nil {
			apiFail(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": j.ID, "status": j.Status})
	}
}

func (s *Server) apiUsage(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoad(w, r)
	if c == nil {
		return
	}
	p, _ := s.store.PackageByID(r.Context(), c.PackageID)
	u, err := s.store.LastUsage(r.Context(), c.ID)
	out := map[string]any{"customer_id": c.UUID}
	if err == nil {
		out["at"], out["disk_mb"], out["inodes"], out["databases_mb"], out["memory_mb"], out["cpu_seconds"], out["processes"] =
			u.At, u.DiskKB/1024, u.Inodes, u.DBB>>20, u.MemoryB>>20, u.CPUUsec/1_000_000, u.Tasks
	}
	if p != nil {
		out["limits"] = map[string]int{"disk_mb": p.Limits.DiskMB, "inodes": p.Limits.Inodes, "memory_mb": p.Limits.MemoryMB, "cpu_percent": p.Limits.CPUPercent,
			"sites": p.MaxSites, "databases": p.MaxDBs, "dns_zones": p.MaxZones}
	}
	sites, dbs, zones, _ := s.store.CountFor(r.Context(), c.ID)
	out["sites"], out["databases"], out["dns_zones"] = sites, dbs, zones
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiSSO(w http.ResponseWriter, r *http.Request) {
	c := s.apiLoad(w, r)
	if c == nil {
		return
	}
	if c.Status != store.StatusActive {
		apiError(w, http.StatusConflict, "conflict", "the customer is "+c.Status)
		return
	}
	tok, exp, err := s.store.CreateSSOLink(r.Context(), c.UserID, "api:"+apiToken(r).Name)
	if err != nil {
		apiFail(w, err)
		return
	}
	s.apiAudit(r, "customer.sso", "customer:"+c.Username, "one-time sign-in link made")
	writeJSON(w, http.StatusCreated, map[string]any{"url": s.panelURL(r.Context(), r) + "/sso/" + tok, "expires_at": exp.UTC()})
}

func (s *Server) apiJob(w http.ResponseWriter, r *http.Request) {
	j, err := s.store.JobByID(r.Context(), r.PathValue("id"))
	if err != nil {
		apiFail(w, err)
		return
	}
	out := map[string]any{"id": j.ID, "kind": j.Kind, "status": j.Status, "created_at": j.CreatedAt.UTC()}
	if j.Error != "" {
		out["error"] = j.Error
	}
	if j.FinishedAt != nil {
		out["finished_at"] = j.FinishedAt.UTC()
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- for EmailZit (P5/P6)

func (s *Server) apiDomain(w http.ResponseWriter, r *http.Request) {
	d, err := hosting.NormalizeDomain(r.PathValue("domain"))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	out := map[string]any{"domain": d, "dns_hosted": false}
	if z, err := s.store.ZoneFor(r.Context(), d); err == nil {
		if c, err := s.store.CustomerByID(r.Context(), z.CustomerID); err == nil {
			out["customer_id"], out["zone"], out["dns_hosted"] = c.UUID, z.Name, true
		}
	} else if x, err := s.store.SiteForName(r.Context(), d); err == nil {
		if c, err := s.store.CustomerByID(r.Context(), x.CustomerID); err == nil {
			out["customer_id"] = c.UUID
		}
	}
	if _, ok := out["customer_id"]; !ok {
		apiError(w, http.StatusNotFound, "not_found", "the domain is not on this server")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) ownedZone(w http.ResponseWriter, r *http.Request) (*store.Zone, string) {
	owner := r.PathValue("owner")
	if owner != "emailzit" {
		apiError(w, http.StatusForbidden, "forbidden", "unknown owner")
		return nil, ""
	}
	name, err := hosting.NormalizeDomain(r.PathValue("zone"))
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid", err.Error())
		return nil, ""
	}
	z, err := s.store.ZoneByName(r.Context(), name)
	if err != nil {
		apiError(w, http.StatusNotFound, "not_found", "the zone is not hosted here")
		return nil, ""
	}
	return z, owner
}

func (s *Server) apiOwned(w http.ResponseWriter, r *http.Request) {
	z, owner := s.ownedZone(w, r)
	if z == nil {
		return
	}
	recs, err := s.store.Records(r.Context(), z.ID)
	if err != nil {
		apiFail(w, err)
		return
	}
	out := []hosting.Record{}
	for _, x := range recs {
		if x.Owner == owner {
			out = append(out, x.Record)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"zone": z.Name, "records": out})
}

func (s *Server) apiOwnedPut(w http.ResponseWriter, r *http.Request) {
	z, owner := s.ownedZone(w, r)
	if z == nil {
		return
	}
	var in struct {
		CustomerID string           `json:"customer_id"`
		Records    []hosting.Record `json:"records"`
	}
	if r.Method == http.MethodPut {
		if err := readJSON(r, &in); err != nil {
			apiError(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
		c, err := s.store.CustomerByID(r.Context(), z.CustomerID)
		if err != nil || !strings.EqualFold(c.UUID, in.CustomerID) {
			apiError(w, http.StatusForbidden, "forbidden", "the zone belongs to another customer")
			return
		}
		if len(in.Records) > 200 {
			apiError(w, http.StatusBadRequest, "invalid", "too many records")
			return
		}
		for i := range in.Records {
			in.Records[i].Owner = owner
			c, err := hosting.CleanRecord(in.Records[i], z.Name)
			if err == nil {
				err = hosting.AllowedForEmailZit(c)
			}
			if err != nil {
				apiError(w, http.StatusBadRequest, "invalid", err.Error())
				return
			}
		}
	}
	conflicts, err := s.store.ReplaceOwnedRecords(r.Context(), z, owner, in.Records)
	if err != nil {
		apiFail(w, err)
		return
	}
	if err := s.applyZone(r.Context(), apiActor(r), z); err != nil {
		apiError(w, http.StatusBadGateway, "internal", storeErr(err))
		return
	}
	s.apiAudit(r, "dns.owned", "zone:"+z.Name, "%s published %d records (%d conflicts)", owner, len(in.Records), len(conflicts))
	if len(conflicts) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": apiErr{Code: "record_conflict", Message: "the customer has own records with these names"}, "conflicts": conflicts})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"zone": z.Name, "records": len(in.Records)})
}

// ---- tokens on the account page

func (s *Server) handleAPITokenCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var scopes []string
	for _, sc := range store.Scopes {
		if r.FormValue("scope_"+sc) != "" {
			scopes = append(scopes, sc)
		}
	}
	id, tok, err := s.store.CreateAPIToken(r.Context(), u.ID, r.FormValue("name"), formInt(r, "days"), scopes)
	if err != nil {
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, storeErr(err))
		return
	}
	s.audit(r, "api.token.create", "user:"+u.Username, "API token #%d %q created (%s)", id, r.FormValue("name"), strings.Join(scopes, " "))
	s.showAccount(w, r, http.StatusOK, &accountData{NewToken: tok}, "")
}

func (s *Server) handleAPITokenDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	name, err := s.store.DeleteAPIToken(r.Context(), u.ID, id)
	if err != nil {
		s.notFound(w, r)
		return
	}
	s.audit(r, "api.token.delete", "user:"+u.Username, "API token #%d %q revoked", id, name)
	s.redirect(w, r, "/account#api", "API token revoked.")
}

var apiExtra []func(s *Server, need func(scope, pattern string, h http.HandlerFunc))
