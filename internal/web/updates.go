package web

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Updates: signed releases checked and installed by the helper.

const settingUpdates = "updates"

// UpdateSettings choose where releases come from.
type UpdateSettings struct {
	Channel string `json:"channel"` // official or testing
	Source  string `json:"source"`  // "" = GitHub; a mirror or file:// for tests
}

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/updates", s.handleUpdates)
		admin("POST /settings/updates", s.handleUpdatesSave)
		admin("POST /settings/updates/install", s.handleUpdateInstall)
	})
}

type updatesData struct {
	U       UpdateSettings
	Latest  map[string]any
	Err     string
	Current string
}

func (s *Server) updateSettings(ctx context.Context) UpdateSettings {
	u := UpdateSettings{Channel: "official"}
	_ = s.store.GetSetting(ctx, settingUpdates, &u)
	return u
}

func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	u := s.updateSettings(r.Context())
	d := &updatesData{U: u, Current: s.Version}
	if r.FormValue("check") != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if err := s.call(ctx, actor(r), "update.check", map[string]string{"source": u.Source, "channel": u.Channel, "current": s.Version}, &d.Latest); err != nil {
			d.Err = storeErr(err)
		}
	}
	s.render(w, r, http.StatusOK, "updates", &Page{Title: "Updates", Nav: "settings", Data: d})
}

func (s *Server) handleUpdatesSave(w http.ResponseWriter, r *http.Request) {
	u := UpdateSettings{Channel: r.FormValue("channel"), Source: strings.TrimSpace(r.FormValue("source"))}
	if u.Channel != "testing" {
		u.Channel = "official"
	}
	if u.Source != "" && !strings.HasPrefix(u.Source, "https://") && !strings.HasPrefix(u.Source, "file:///") {
		s.redirectErr(w, r, "/settings/updates", "The update source must start with https://")
		return
	}
	if err := s.store.SetSetting(r.Context(), settingUpdates, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.updates", "settings", "channel %s, source %q", u.Channel, u.Source)
	s.redirect(w, r, "/settings/updates?check=1", "Saved.")
}

func (s *Server) handleUpdateInstall(w http.ResponseWriter, r *http.Request) {
	u := s.updateSettings(r.Context())
	v := strings.TrimSpace(r.FormValue("version"))
	var res map[string]string
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()
	s.audit(r, "update.install", "server", "installing %s (channel %s)", v, u.Channel)
	if err := s.call(ctx, actor(r), "update.install", map[string]string{"source": u.Source, "channel": u.Channel, "version": v, "current": s.Version}, &res); err != nil {
		s.redirectErr(w, r, "/settings/updates", storeErr(err))
		return
	}
	s.redirect(w, r, "/settings/updates", "The new version is being installed; the panel restarts in a moment. Reload the page in a minute.")
}
