package helper

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
)

// WP-CLI runs as the account inside its cage (like the account's own PHP),
// so it can never touch another account. The command list keeps the panel
// to the commands it needs.

var wpCommands = map[string]bool{
	"core": true, "plugin": true, "theme": true, "option": true, "config": true, "user": true, "search-replace": true, "db": true,
	"maintenance-mode": true, "cache": true, "redis": true, "rewrite": true, "language": true, "cron": true, "transient": true, "site": true, "post": true,
}

var wpBlocked = []string{"--exec", "--require", "eval", "eval-file", "shell", "package", "--ssh", "--http", "server", "--path"}

var wpArgRE = regexp.MustCompile(`^[\p{L}\p{N} _@.:/,=+%#*'"()&?!~\[\]{}<>$-]{0,1000}$`)

type wpArgs struct {
	Account string   `json:"account"`
	Path    string   `json:"path"` // WordPress folder relative to the home (sites/…)
	Args    []string `json:"args"`
	Stdin   string   `json:"stdin,omitempty"`
}

// WPResult is the output of WP-CLI.
type WPResult struct {
	Output string `json:"output"`
	OK     bool   `json:"ok"`
}

func checkWP(a wpArgs) (string, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return "", userErr(err.Error())
	}
	p, err := hosting.CleanRelPath(a.Path)
	if err != nil || !strings.HasPrefix(p, "sites/") {
		return "", userErr("WordPress must be in a folder inside sites/")
	}
	if len(a.Args) == 0 || len(a.Args) > 40 || !wpCommands[a.Args[0]] {
		return "", userErr("this WP-CLI command is not allowed")
	}
	for _, x := range a.Args {
		if !wpArgRE.MatchString(x) {
			return "", userErr("invalid WP-CLI argument")
		}
		for _, b := range wpBlocked {
			if x == b || strings.HasPrefix(x, b+"=") {
				return "", userErr("this WP-CLI option is not allowed")
			}
		}
	}
	if len(a.Stdin) > 4096 {
		return "", userErr("input too long")
	}
	return hosting.HomeDir(a.Account) + "/" + p, nil
}

func (h *Helper) wp(ctx context.Context, a wpArgs) (any, error) {
	dir, err := checkWP(a)
	if err != nil {
		return nil, err
	}
	argv := append([]string{"/usr/local/bin/wp", "--path=" + dir, "--no-color"}, a.Args...)
	var in []byte
	if a.Stdin != "" {
		in = []byte(a.Stdin)
	}
	out, err := h.inCage(ctx, a.Account, in, argv...)
	if err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			return nil, err
		}
		return WPResult{Output: tail(string(out)+"\n"+err.Error(), 4000), OK: false}, nil
	}
	return WPResult{Output: tail(string(out), 64000), OK: true}, nil
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

var snapNameRE = regexp.MustCompile(`^[a-z0-9-]{1,80}$`)

type snapArgs struct {
	Account string `json:"account"`
	Path    string `json:"path"`
	Name    string `json:"name"` // file name without extension
}

// wpSnapshot saves the WordPress folder and its database into
// ~/backups/<name>.tar.gz (the dump goes into the archive as db.sql).
func (h *Helper) wpSnapshot(ctx context.Context, a snapArgs) (any, error) {
	dir, err := checkWP(wpArgs{Account: a.Account, Path: a.Path, Args: []string{"db"}})
	if err != nil {
		return nil, err
	}
	if !snapNameRE.MatchString(a.Name) {
		return nil, userErr("invalid snapshot name")
	}
	home := hosting.HomeDir(a.Account)
	dump := home + "/backups/" + a.Name + ".sql"
	file := home + "/backups/" + a.Name + ".tar.gz"
	if out, err := h.inCage(ctx, a.Account, nil, "/usr/local/bin/wp", "--path="+dir, "--no-color", "db", "export", dump); err != nil {
		return nil, userErr("database export failed: " + tail(string(out)+" "+err.Error(), 400))
	}
	rel := strings.TrimPrefix(dir, home+"/")
	out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/tar", "-czf", file, "-C", home, rel, "backups/"+a.Name+".sql")
	_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/rm", "-f", dump)
	if err != nil {
		return nil, userErr("archive failed: " + tail(string(out)+" "+err.Error(), 400))
	}
	st, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "stat", Path: "backups/" + a.Name + ".tar.gz"}})
	size := int64(0)
	if err == nil {
		if r, ok := st.(WorkerResp); ok && r.File != nil {
			size = r.File.Size
		}
	}
	return map[string]any{"file": "backups/" + a.Name + ".tar.gz", "size": size}, nil
}

// wpRestore puts a snapshot back: the folder is replaced, the database
// imported again.
func (h *Helper) wpRestore(ctx context.Context, a snapArgs) (any, error) {
	dir, err := checkWP(wpArgs{Account: a.Account, Path: a.Path, Args: []string{"db"}})
	if err != nil {
		return nil, err
	}
	if !snapNameRE.MatchString(a.Name) {
		return nil, userErr("invalid snapshot name")
	}
	home := hosting.HomeDir(a.Account)
	file := home + "/backups/" + a.Name + ".tar.gz"
	rel := strings.TrimPrefix(dir, home+"/")
	// the old folder goes aside first, so a failed restore can be undone by hand
	aside := rel + ".before-" + a.Name
	_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/rm", "-rf", home+"/"+aside)
	if out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/mv", home+"/"+rel, home+"/"+aside); err != nil {
		return nil, userErr("could not move the site aside: " + tail(string(out), 300))
	}
	if out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/tar", "-xzf", file, "-C", home, "--no-same-owner", "--no-same-permissions", rel, "backups/"+a.Name+".sql"); err != nil {
		_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/mv", home+"/"+aside, home+"/"+rel)
		return nil, userErr("could not unpack the snapshot: " + tail(string(out)+" "+err.Error(), 300))
	}
	dump := home + "/backups/" + a.Name + ".sql"
	out, err := h.inCage(ctx, a.Account, nil, "/usr/local/bin/wp", "--path="+dir, "--no-color", "db", "import", dump)
	_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/rm", "-f", dump)
	if err != nil {
		return nil, userErr("the files are back but the database import failed: " + tail(string(out)+" "+err.Error(), 300))
	}
	_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/rm", "-rf", home+"/"+aside)
	return nil, nil
}

type copyArgs struct {
	Account string   `json:"account"`
	From    string   `json:"from"` // folder inside sites/
	To      string   `json:"to"`
	Keep    []string `json:"keep"` // file names in To that survive (wp-config.php)
}

var keepRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// siteCopy replaces the folder To with a copy of From, as the account in
// its cage; the files named in Keep stay as they were in To.
func (h *Helper) siteCopy(ctx context.Context, a copyArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	from, err1 := hosting.CleanRelPath(a.From)
	to, err2 := hosting.CleanRelPath(a.To)
	if err1 != nil || err2 != nil || !strings.HasPrefix(from, "sites/") || !strings.HasPrefix(to, "sites/") || from == to ||
		strings.HasPrefix(to+"/", from+"/") || strings.HasPrefix(from+"/", to+"/") {
		return nil, userErr("both folders must be separate folders inside sites/")
	}
	home := hosting.HomeDir(a.Account)
	tmp := home + "/.hz-keep"
	run := func(argv ...string) error {
		out, err := h.inCage(ctx, a.Account, nil, argv...)
		if err != nil {
			return userErr(argv[0] + ": " + tail(string(out)+" "+err.Error(), 300))
		}
		return nil
	}
	_ = run("/usr/bin/rm", "-rf", tmp)
	if err := run("/usr/bin/mkdir", "-p", tmp, home+"/"+to); err != nil {
		return nil, err
	}
	for _, k := range a.Keep {
		if !keepRE.MatchString(k) {
			return nil, userErr("invalid file name")
		}
		_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/mv", home+"/"+to+"/"+k, tmp+"/"+k)
	}
	if err := run("/usr/bin/rm", "-rf", home+"/"+to); err != nil {
		return nil, err
	}
	if err := run("/usr/bin/cp", "-a", home+"/"+from, home+"/"+to); err != nil {
		return nil, err
	}
	for _, k := range a.Keep {
		_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/mv", "-f", tmp+"/"+k, home+"/"+to+"/"+k)
	}
	_ = run("/usr/bin/rm", "-rf", tmp)
	return nil, nil
}
