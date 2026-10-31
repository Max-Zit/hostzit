package hosting

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Git deployment (like cPanel's Git Version Control): bare repositories in
// ~/repos/<name>.git; a push over SSH or a pull from a remote address
// checks the branch out into a folder of a website and runs the optional
// script .hostzit-deploy there, as the account inside its cage.

// GitRepo is a repository of an account.
type GitRepo struct {
	Name   string `json:"name"`
	Branch string `json:"branch"`
	Target string `json:"target"` // folder below the home, e.g. sites/example.com/public
	Remote string `json:"remote,omitempty"`
}

var (
	gitNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	gitBranchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$`)
	gitRemoteRE = regexp.MustCompile(`^https://[A-Za-z0-9._~:%@!$&'()*+,;=/-]{3,500}$`)
	gitTargetRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,300}$`)
)

// Validate checks the repository's settings.
func (g GitRepo) Validate() error {
	if !gitNameRE.MatchString(g.Name) || strings.HasSuffix(g.Name, ".git") {
		return errors.New("name: lower-case letters, digits, dots, dashes (up to 63)")
	}
	if !gitBranchRE.MatchString(g.Branch) || strings.Contains(g.Branch, "..") || strings.HasSuffix(g.Branch, "/") || strings.HasSuffix(g.Branch, ".lock") {
		return errors.New("invalid branch name")
	}
	p, err := CleanRelPath(g.Target)
	if err != nil || p != g.Target || !strings.HasPrefix(p, "sites/") || !gitTargetRE.MatchString(p) || strings.Count(p, "/") < 1 {
		return errors.New("the target must be a folder inside sites/")
	}
	if g.Remote != "" && (!gitRemoteRE.MatchString(g.Remote) || strings.Contains(g.Remote, "..")) {
		return errors.New("the remote must be an https:// address")
	}
	return nil
}

// Dir is the bare repository below the home.
func (g GitRepo) Dir() string { return "repos/" + g.Name + ".git" }

// GitHook renders the post-receive hook: a push to the branch is checked
// out into the target folder.
func GitHook(account string, g GitRepo) string {
	home := HomeDir(account)
	return fmt.Sprintf(`#!/bin/sh
# HostZit (generated): a push to %[1]s is deployed into %[2]s.
while read old new ref; do
	[ "$ref" = "refs/heads/%[1]s" ] || continue
	%[3]s/repos/%[4]s.git/hooks/hostzit-deploy
done
`, g.Branch, g.Target, home, g.Name)
}

// GitDeployScript checks the branch out and runs .hostzit-deploy; it keeps
// its output in deploy.log next to the repository.
func GitDeployScript(account string, g GitRepo) string {
	home := HomeDir(account)
	return fmt.Sprintf(`#!/bin/sh
# HostZit (generated): deploys the branch %[1]s into %[2]s.
repo=%[3]s/repos/%[4]s.git
work=%[3]s/%[2]s
{
	echo "== $(date -u '+%%Y-%%m-%%d %%H:%%M:%%S') UTC: %[1]s -> %[2]s"
	mkdir -p "$work" &&
	git --git-dir="$repo" --work-tree="$work" checkout -f %[1]s &&
	if [ -f "$work/.hostzit-deploy" ]; then
		echo "== .hostzit-deploy"
		(cd "$work" && timeout 600 sh ./.hostzit-deploy)
	fi
	echo "== exit $?"
} > "$repo/deploy.log" 2>&1
cat "$repo/deploy.log"
grep -q '^== exit 0$' "$repo/deploy.log"
`, g.Branch, g.Target, home, g.Name)
}
