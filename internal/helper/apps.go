package helper

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Node.js and Python applications of an account (see hosting.App).

// applyApps installs missing runtimes, writes the units and starts what
// changed; applications no longer listed are stopped and removed.
func (h *Helper) applyApps(ctx context.Context, a hosting.Account) error {
	need := map[string]bool{}
	for _, app := range a.Apps {
		for _, p := range hosting.AppKinds[app.Kind] {
			need[p] = true
		}
	}
	var missing []string
	for p := range need {
		bin := map[string]string{"nodejs": "/usr/bin/node", "npm": "/usr/bin/npm", "python3": "/usr/bin/python3", "python3-pip": "/usr/bin/pip3"}[p]
		if bin == "" {
			bin = "/usr/share/doc/" + p
		}
		if !h.Sys.Exists(bin) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		if out, err := h.apt(ctx, append([]string{"install", "--no-install-recommends"}, missing...)...); err != nil {
			return userErr("the runtime could not be installed: " + tail(string(out), 300))
		}
	}
	want := map[string]bool{}
	var changed []string
	for _, app := range a.Apps {
		u := hosting.AppUnitName(a.Name, app.Name)
		want[u] = true
		text, err := hosting.AppUnit(a, app)
		if err != nil {
			return err
		}
		old, _ := h.Sys.ReadFile(systemdDir + u)
		if string(old) != text {
			if err := h.Sys.WriteFile(systemdDir+u, []byte(text), 0o644, 0, 0); err != nil {
				return err
			}
			changed = append(changed, u)
		}
	}
	prefix := "hz-app-" + a.Name + "-"
	ents, _ := h.Sys.ReadDir(systemdDir)
	reload := len(changed) > 0
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ".service") && !want[n] {
			_ = h.systemctl(ctx, "disable", "--now", n)
			_ = h.Sys.Remove(systemdDir + n)
			reload = true
		}
	}
	if reload {
		if err := h.systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	for u := range want {
		if a.Suspended {
			_ = h.systemctl(ctx, "disable", "--now", u)
			continue
		}
		_ = h.systemctl(ctx, "enable", u)
		if slices.Contains(changed, u) {
			_ = h.systemctl(ctx, "restart", u)
		} else {
			_ = h.systemctl(ctx, "start", u)
		}
	}
	return nil
}

type appArgs struct {
	Account string `json:"account"`
	Name    string `json:"name"`
	Lines   int    `json:"lines,omitempty"`
}

func (a appArgs) unit() (string, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return "", userErr(err.Error())
	}
	if (hosting.App{Name: a.Name, Kind: "node", Root: "x", Command: "x"}).Validate() != nil {
		return "", userErr("invalid application name")
	}
	return hosting.AppUnitName(a.Account, a.Name), nil
}

func (h *Helper) appRestart(ctx context.Context, a appArgs) (any, error) {
	u, err := a.unit()
	if err != nil {
		return nil, err
	}
	if !h.Sys.Exists(systemdDir + u) {
		return nil, userErr("the application is not set up")
	}
	return nil, h.systemctl(ctx, "restart", u)
}

// AppState is what the panel shows of an application.
type AppState struct {
	State    string `json:"state"` // active, failed, inactive …
	Since    string `json:"since"`
	Restarts int    `json:"restarts"`
	MemoryB  int64  `json:"memory_b"`
	Log      string `json:"log,omitempty"`
}

func (h *Helper) appStatus(ctx context.Context, a appArgs) (any, error) {
	u, err := a.unit()
	if err != nil {
		return nil, err
	}
	var st AppState
	out, _ := h.Sys.Run(ctx, nil, "systemctl", "show", "-p", "ActiveState,ActiveEnterTimestamp,NRestarts,MemoryCurrent", u)
	for _, l := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "ActiveState":
			st.State = v
		case "ActiveEnterTimestamp":
			st.Since = v
		case "NRestarts":
			st.Restarts, _ = strconv.Atoi(v)
		case "MemoryCurrent":
			st.MemoryB, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if a.Lines > 0 {
		n := min(a.Lines, 1000)
		out, _ := h.Sys.Run(ctx, nil, "journalctl", "-u", u, "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso", "--no-hostname")
		st.Log = tail(string(out), 64000)
	}
	return st, nil
}

type appRunArgs struct {
	Account string `json:"account"`
	Root    string `json:"root"`
	Command string `json:"command"`
}

// appRun runs a one-off command (npm ci, pip install …) in the folder of
// an application, as the account in its cage, for at most 15 minutes.
func (h *Helper) appRun(ctx context.Context, a appRunArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if err := (hosting.App{Name: "x", Kind: "node", Root: a.Root, Command: a.Command}).Validate(); err != nil {
		return nil, userErr(err.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	dir := hosting.HomeDir(a.Account) + "/" + a.Root
	script := "cd " + shQuote(dir) + " && export PATH=" + shQuote(dir+"/node_modules/.bin:"+dir+"/.venv/bin:/usr/local/bin:/usr/bin:/bin") + " && " + a.Command
	out, err := h.inCage(ctx, a.Account, nil, "/bin/sh", "-c", script)
	res := map[string]any{"ok": err == nil, "output": tail(string(out), 32000)}
	if err != nil {
		res["output"] = tail(string(out)+"\n"+err.Error(), 32000)
	}
	return res, nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["app.restart"] = op{handle(h.appRestart), false}
		h.ops["app.status"] = op{handle(h.appStatus), false}
		h.ops["app.run"] = op{handle(h.appRun), false}
	})
}
