package helper

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Git repositories of an account (see hosting.GitRepo). Everything inside
// the home runs as the account in its cage; only installing git is root.

type gitArgs struct {
	Account string          `json:"account"`
	Repo    hosting.GitRepo `json:"repo"`
	Pull    bool            `json:"pull,omitempty"`
}

// GitResult is the output of a deployment.
type GitResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

func (h *Helper) ensureGit(ctx context.Context) error {
	if h.Sys.Exists("/usr/bin/git") {
		return nil
	}
	if out, err := h.apt(ctx, "install", "--no-install-recommends", "git"); err != nil {
		return userErr("git could not be installed: " + tail(string(out), 300))
	}
	return nil
}

func (a gitArgs) check() error {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return userErr(err.Error())
	}
	if err := a.Repo.Validate(); err != nil {
		return userErr(err.Error())
	}
	return nil
}

func (h *Helper) git(ctx context.Context, account string, args ...string) ([]byte, error) {
	// no password prompt: a private remote carries its token in the address
	return h.inCage(ctx, account, nil, append([]string{"/usr/bin/env", "GIT_TERMINAL_PROMPT=0", "/usr/bin/git"}, args...)...)
}

// gitSetup creates the repository or updates its branch, remote and hooks.
func (h *Helper) gitSetup(ctx context.Context, a gitArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	if err := h.ensureGit(ctx); err != nil {
		return nil, err
	}
	home := hosting.HomeDir(a.Account)
	dir := home + "/" + a.Repo.Dir()
	if _, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "mkdir", Path: "repos"}}); err != nil {
		return nil, err
	}
	if _, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "stat", Path: a.Repo.Dir() + "/HEAD"}}); err != nil {
		if out, err := h.git(ctx, a.Account, "init", "--bare", "--quiet", "--initial-branch="+a.Repo.Branch, dir); err != nil {
			return nil, userErr("git init failed: " + tail(string(out), 300))
		}
	}
	_, _ = h.git(ctx, a.Account, "--git-dir="+dir, "remote", "remove", "origin")
	if a.Repo.Remote != "" {
		if out, err := h.git(ctx, a.Account, "--git-dir="+dir, "remote", "add", "origin", a.Repo.Remote); err != nil {
			return nil, userErr("git remote failed: " + tail(string(out), 300))
		}
	}
	for name, text := range map[string]string{"post-receive": hosting.GitHook(a.Account, a.Repo), "hostzit-deploy": hosting.GitDeployScript(a.Account, a.Repo)} {
		p := a.Repo.Dir() + "/hooks/" + name
		if _, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "write", Path: p, Data: []byte(text)}}); err != nil {
			return nil, err
		}
		if _, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "chmod", Path: p, Mode: "755"}}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// gitDeploy fetches the remote (pull) and deploys the branch.
func (h *Helper) gitDeploy(ctx context.Context, a gitArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	dir := hosting.HomeDir(a.Account) + "/" + a.Repo.Dir()
	var b strings.Builder
	if a.Pull {
		if a.Repo.Remote == "" {
			return nil, userErr("the repository has no remote address")
		}
		fctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		out, err := h.git(fctx, a.Account, "--git-dir="+dir, "fetch", "--prune", "--quiet", "origin", "+refs/heads/*:refs/heads/*")
		cancel()
		b.WriteString(redactURL(string(out)))
		if err != nil {
			return GitResult{Output: tail(b.String()+"\nfetch failed: "+redactURL(err.Error()), 8000)}, nil
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 11*time.Minute)
	defer cancel()
	out, err := h.inCage(dctx, a.Account, nil, "/bin/sh", dir+"/hooks/hostzit-deploy")
	b.Write(out)
	var ue *UserError
	if errors.As(err, &ue) {
		return nil, err
	}
	return GitResult{OK: err == nil, Output: tail(b.String(), 8000)}, nil
}

// redactURL hides a password or token in an https address.
func redactURL(s string) string {
	i := strings.Index(s, "https://")
	if i < 0 {
		return s
	}
	rest := s[i+8:]
	end := strings.IndexAny(rest, " \n\t'\"/")
	if end < 0 {
		end = len(rest)
	}
	if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
		return s[:i+8] + "…@" + redactURL(rest[at+1:])
	}
	return s[:i+8] + redactURL(rest)
}

// GitCommit is a commit of the deployed branch.
type GitCommit struct {
	Hash    string `json:"hash"`
	Author  string `json:"author"`
	Date    string `json:"date"`
	Subject string `json:"subject"`
}

// GitInfo is shown in the panel.
type GitInfo struct {
	Commits []GitCommit `json:"commits"`
	Log     string      `json:"log"` // last deployment
}

func (h *Helper) gitInfo(ctx context.Context, a gitArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	dir := hosting.HomeDir(a.Account) + "/" + a.Repo.Dir()
	var info GitInfo
	if out, err := h.git(ctx, a.Account, "--git-dir="+dir, "log", "-n", "10", "--format=%h%x1f%an%x1f%ad%x1f%s", "--date=format:%Y-%m-%d %H:%M", a.Repo.Branch, "--"); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if f := strings.Split(l, "\x1f"); len(f) == 4 {
				info.Commits = append(info.Commits, GitCommit{Hash: f[0], Author: f[1], Date: f[2], Subject: f[3]})
			}
		}
	}
	if r, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "read", Path: a.Repo.Dir() + "/deploy.log", Limit: 64 << 10}}); err == nil {
		if wr, ok := r.(WorkerResp); ok {
			info.Log = tail(string(wr.Data), 8000)
		}
	}
	return info, nil
}

func (h *Helper) gitDelete(ctx context.Context, a gitArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	return h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "delete", Path: a.Repo.Dir()}})
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["git.setup"] = op{handle(h.gitSetup), false}
		h.ops["git.deploy"] = op{handle(h.gitDeploy), false}
		h.ops["git.info"] = op{handle(h.gitInfo), false}
		h.ops["git.delete"] = op{handle(h.gitDelete), false}
	})
}
