package hosting

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Node.js and Python applications of an account (like cPanel's "Setup
// Node.js App" and "Setup Python App"): a long-running process in the
// account's cage and slice that listens on a Unix socket. Its address is
// in the environment variable PORT (Node.js: app.listen(process.env.PORT);
// Python: gunicorn --bind unix:$PORT app:app); nginx sends the requests of
// a website to it.

// App is one application.
type App struct {
	Name    string            `json:"name"`
	Kind    string            `json:"kind"` // node or python
	Root    string            `json:"root"` // folder below the home
	Command string            `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
}

// AppKinds are the runtimes and their Debian packages.
var AppKinds = map[string][]string{
	"node":   {"nodejs", "npm"},
	"python": {"python3", "python3-venv", "python3-pip"},
}

var (
	appNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	appRootRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,300}$`)
	appEnvRE  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
)

// Validate checks an application.
func (a App) Validate() error {
	if !appNameRE.MatchString(a.Name) {
		return errors.New("name: lower-case letters, digits and dashes (up to 31), starting with a letter")
	}
	if _, ok := AppKinds[a.Kind]; !ok {
		return errors.New("unknown kind of application")
	}
	p, err := CleanRelPath(a.Root)
	if err != nil || p != a.Root || !appRootRE.MatchString(p) || p == "." {
		return errors.New("the folder must be inside your home, e.g. apps/shop")
	}
	if a.Command == "" || len(a.Command) > 500 || strings.ContainsAny(a.Command, "\n\r\x00") {
		return errors.New("enter the start command (one line)")
	}
	if len(a.Env) > 50 {
		return errors.New("at most 50 environment variables")
	}
	for k, v := range a.Env {
		if !appEnvRE.MatchString(k) || k == "PORT" || k == "HOME" || k == "PATH" {
			return fmt.Errorf("invalid environment variable %q", k)
		}
		if len(v) > 2000 || strings.ContainsAny(v, "\n\r\x00") {
			return fmt.Errorf("the value of %s must be one line", k)
		}
	}
	return nil
}

// AppUnitName names the systemd unit.
func AppUnitName(account, app string) string { return "hz-app-" + account + "-" + app + ".service" }

// AppSocket is the application's socket inside the cage.
func AppSocket(app string) string { return "/.sock/app-" + app + ".sock" }

// AppSocketHost is the socket's path on the host (nginx).
func AppSocketHost(account, app string) string { return CageDir(account) + AppSocket(app) }

// systemdQuote quotes a value for an Environment= line.
func systemdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`).Replace(s) + `"`
}

// AppUnit renders the application's unit. The command runs through
// /bin/sh in the folder of the application; the socket is opened for nginx
// once it exists (the .sock folder keeps other accounts out).
func AppUnit(a Account, app App) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	if err := app.Validate(); err != nil {
		return "", err
	}
	sock := AppSocket(app.Name)
	var extra strings.Builder
	fmt.Fprintf(&extra, "WorkingDirectory=%s/%s\n", HomeDir(a.Name), app.Root)
	fmt.Fprintf(&extra, "Environment=HOME=%s PORT=%s HZ_SOCKET=%s TMPDIR=/tmp LANG=C.UTF-8 PATH=%s/%s/node_modules/.bin:%s/%s/.venv/bin:/usr/local/bin:/usr/bin:/bin\n",
		HomeDir(a.Name), sock, sock, HomeDir(a.Name), app.Root, HomeDir(a.Name), app.Root)
	if app.Kind == "node" {
		extra.WriteString("Environment=NODE_ENV=production\n")
	}
	keys := make([]string, 0, len(app.Env))
	for k := range app.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&extra, "Environment=%s\n", systemdQuote(k+"="+app.Env[k]))
	}
	fmt.Fprintf(&extra, "ExecStartPre=-/bin/rm -f %s\n", sock)
	fmt.Fprintf(&extra, "ExecStartPost=/bin/sh -c 'i=0; while [ $$i -lt 150 ]; do if [ -S %[1]s ]; then exec chmod 666 %[1]s; fi; i=$$((i+1)); sleep 0.2; done'\n", sock)
	// only the socket: no TCP or UDP port of its own on the server
	extra.WriteString("SocketBindDeny=any\nRestart=always\n")
	exec := "/bin/sh -c " + systemdQuote("exec "+app.Command)
	return cagedService(a, "Application "+app.Name+" of hosting account "+a.Name, "simple", exec, extra.String()), nil
}
