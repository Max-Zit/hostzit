package helper

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/update"
)

// Self-update: the helper fetches the release manifest, checks its
// signature against the release keys built into this program (the panel
// has no say in that), downloads the Debian package, checks its SHA-256,
// saves the panel database and installs the package.

// UpdateCache keeps downloaded packages and database dumps.
const UpdateCache = "/var/cache/hostzit"

type updateArgs struct {
	Source  string `json:"source"`  // "" = the official releases on GitHub
	Channel string `json:"channel"` // official or testing
	Version string `json:"version"` // to install ("" = only check)
	Current string `json:"current"` // the running version
}

func validSource(s string) bool {
	return s == "" || (strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "file:///")) && !strings.ContainsAny(s, " \r\n\"'`<>") && len(s) < 300
}

// updateCheck reports the newest release of a channel.
func (h *Helper) updateCheck(ctx context.Context, a updateArgs) (any, error) {
	if !validSource(a.Source) {
		return nil, userErr("invalid update source")
	}
	src := a.Source
	if src == "" {
		src = update.DefaultSource
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	m, err := update.Latest(ctx, &http.Client{Timeout: time.Minute}, src, a.Channel)
	if err != nil {
		return nil, userErr("no release information: " + err.Error())
	}
	return map[string]any{"version": m.Version, "released": m.Released, "notes": m.Notes, "newer": a.Current == "" || update.Newer(m.Version, a.Current)}, nil
}

// updateInstall installs a signed release.
func (h *Helper) updateInstall(ctx context.Context, a updateArgs) (any, error) {
	if !validSource(a.Source) || a.Version == "" || !update.SafeName(a.Version) {
		return nil, userErr("invalid update request")
	}
	src := a.Source
	if src == "" {
		src = update.DefaultSource
	}
	hc := &http.Client{Timeout: 10 * time.Minute}
	m, _, _, err := update.Fetch(ctx, hc, src, a.Version)
	if err != nil {
		return nil, userErr("the release could not be verified: " + err.Error())
	}
	if a.Current != "" && !update.Newer(m.Version, a.Current) && !strings.Contains(a.Current, "dev") {
		return nil, userErr("this version is not newer than the installed one")
	}
	f := m.Find("server", "deb", "linux-"+runtime.GOARCH)
	if f == nil {
		return nil, userErr("the release has no package for this server")
	}
	if err := os.MkdirAll(UpdateCache, 0o700); err != nil {
		return nil, err
	}
	pkg := filepath.Join(UpdateCache, f.Name)
	if err := update.Download(ctx, hc, src, m.Version, *f, pkg); err != nil {
		return nil, userErr("download: " + err.Error())
	}
	// the panel database first, so a failed update can go back
	dump := filepath.Join(UpdateCache, "hostzit-db-before-"+m.Version+".sql")
	df, err := os.OpenFile(dump, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|noFollowFile, 0o600) // #nosec G304 -- root-only cache, checked version
	if err != nil {
		return nil, err
	}
	out, err := runToFile(ctx, df, "runuser", "-u", "postgres", "--", "pg_dump", "hostzit")
	df.Close()
	if err != nil {
		return nil, fmt.Errorf("database backup: %v %s", err, tail(out, 200))
	}
	if out, err := h.Sys.Run(ctx, nil, "dpkg", "-i", pkg); err != nil {
		return nil, fmt.Errorf("install: %v %s", err, tail(string(out), 400))
	}
	_ = h.systemctl(ctx, "daemon-reload")
	_ = h.systemctl(ctx, "restart", "hostzit-server")
	// the helper itself restarts a moment later, after it answered
	_, _ = h.Sys.Run(ctx, nil, "systemd-run", "--on-active=3", "--unit=hostzit-helper-restart-"+strings.ReplaceAll(m.Version, ".", "-"), "systemctl", "restart", "hostzit-helper")
	h.logf("updated to %s", m.Version)
	return map[string]string{"version": m.Version}, nil
}
