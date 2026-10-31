package web

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// Git deployment in the customer panel (like cPanel's Git Version
// Control): repositories in ~/repos, deployed into a folder of a website
// after a push over SSH, a click or a webhook from GitHub, GitLab, Gitea …

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /git", s.handleGitList)
		c("POST /git", s.handleGitCreate)
		c("GET /git/{id}", s.handleGitRepo)
		c("POST /git/{id}", s.handleGitUpdate)
		c("POST /git/{id}/deploy", s.handleGitDeploy)
		c("POST /git/{id}/delete", s.handleGitDelete)
		// the webhook is called by the Git host: its secret is in the address
		mux.HandleFunc("POST /hooks/git/{token}", s.handleGitHook)
	})
}

func gitSpec(g *store.GitRepo) hosting.GitRepo {
	return hosting.GitRepo{Name: g.Name, Branch: g.Branch, Target: g.Target, Remote: g.Remote}
}

type gitListData struct {
	Repos []*store.GitRepo
	Sites []*store.Site
	SSH   bool
}

func (s *Server) handleGitList(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	d := &gitListData{}
	d.Repos, _ = s.store.GitRepos(r.Context(), c.ID)
	d.Sites, _ = s.store.Sites(r.Context(), c.ID)
	if a, _, err := s.accountFor(r.Context(), c); err == nil {
		d.SSH = a.Limits.SSH
	}
	s.render(w, r, http.StatusOK, "git", &Page{Title: "Git", Nav: "git", Customer: c, Data: d})
}

func (s *Server) handleGitCreate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	g := &store.GitRepo{CustomerID: c.ID, Name: strings.TrimSpace(strings.ToLower(r.FormValue("name"))), Branch: strings.TrimSpace(r.FormValue("branch")),
		Target: strings.Trim(strings.TrimSpace(r.FormValue("target")), "/"), Remote: strings.TrimSpace(r.FormValue("remote")), HookToken: auth.RandomToken(24)}
	if g.Branch == "" {
		g.Branch = "main"
	}
	if err := gitSpec(g).Validate(); err != nil {
		s.redirectErr(w, r, "/git", err.Error())
		return
	}
	if list, _ := s.store.GitRepos(r.Context(), c.ID); len(list) >= 20 {
		s.redirectErr(w, r, "/git", "At most 20 repositories per account.")
		return
	}
	if err := s.call(r.Context(), actor(r), "git.setup", map[string]any{"account": c.Username, "repo": gitSpec(g)}, nil); err != nil {
		s.redirectErr(w, r, "/git", storeErr(err))
		return
	}
	if err := s.store.SaveGitRepo(r.Context(), g); err != nil {
		s.redirectErr(w, r, "/git", storeErr(err))
		return
	}
	s.audit(r, "git.create", "customer:"+c.Username, "repository %s (%s → %s)", g.Name, g.Branch, g.Target)
	if g.Remote != "" {
		s.deployGit(context.WithoutCancel(r.Context()), actor(r), c, g, true)
	}
	http.Redirect(w, r, "/git/"+strconv.FormatInt(g.ID, 10), http.StatusSeeOther)
}

func (s *Server) myGit(w http.ResponseWriter, r *http.Request, c *store.Customer) *store.GitRepo {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	g, err := s.store.GitRepoByID(r.Context(), id)
	if err != nil || g.CustomerID != c.ID {
		s.notFound(w, r)
		return nil
	}
	return g
}

type gitRepoData struct {
	G       *store.GitRepo
	Info    helper.GitInfo
	PushURL string
	HookURL string
	Running bool
}

func (s *Server) handleGitRepo(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	g := s.myGit(w, r, c)
	if g == nil {
		return
	}
	d := &gitRepoData{G: g, Running: gitRunning(g.ID)}
	_ = s.call(r.Context(), actor(r), "git.info", map[string]any{"account": c.Username, "repo": gitSpec(g)}, &d.Info)
	if a, _, err := s.accountFor(r.Context(), c); err == nil && a.Limits.SSH {
		host := s.hostingSettings(r.Context()).ServerName
		if host == "" {
			host = s.hostingSettings(r.Context()).IPv4
		}
		d.PushURL = "ssh://" + c.Username + "@" + strings.TrimSuffix(host, ".") + hosting.HomeDir(c.Username) + "/" + gitSpec(g).Dir()
	}
	if g.Remote != "" {
		d.HookURL = "https://" + r.Host + "/hooks/git/" + g.HookToken
	}
	s.render(w, r, http.StatusOK, "gitrepo", &Page{Title: g.Name, Nav: "git", Customer: c, Crumb: "Git", CrumbURL: "/git", Data: d})
}

func (s *Server) handleGitUpdate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	g := s.myGit(w, r, c)
	if g == nil {
		return
	}
	back := "/git/" + strconv.FormatInt(g.ID, 10)
	g.Branch = strings.TrimSpace(r.FormValue("branch"))
	g.Target = strings.Trim(strings.TrimSpace(r.FormValue("target")), "/")
	if rm := strings.TrimSpace(r.FormValue("remote")); rm != maskRemote(g.Remote) {
		g.Remote = rm
	}
	if err := gitSpec(g).Validate(); err != nil {
		s.redirectErr(w, r, back, err.Error())
		return
	}
	if err := s.call(r.Context(), actor(r), "git.setup", map[string]any{"account": c.Username, "repo": gitSpec(g)}, nil); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	if err := s.store.SaveGitRepo(r.Context(), g); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "git.update", "customer:"+c.Username, "repository %s (%s → %s)", g.Name, g.Branch, g.Target)
	s.redirect(w, r, back, "Saved.")
}

// gitBusy keeps one deployment per repository at a time.
var gitBusy sync.Map

func gitRunning(id int64) bool { _, ok := gitBusy.Load(id); return ok }

// deployGit fetches (pull) and deploys in the background.
func (s *Server) deployGit(ctx context.Context, by string, c *store.Customer, g *store.GitRepo, pull bool) bool {
	if _, busy := gitBusy.LoadOrStore(g.ID, true); busy {
		return false
	}
	_, err := s.runJob("git.deploy", &c.ID, c.Username+"/"+g.Name, func(ctx context.Context) error {
		defer gitBusy.Delete(g.ID)
		var res helper.GitResult
		err := s.call(ctx, by, "git.deploy", map[string]any{"account": c.Username, "repo": gitSpec(g), "pull": pull}, &res)
		_ = s.store.MarkGitDeployed(ctx, g.ID, err == nil && res.OK)
		_ = s.store.Audit(ctx, by, "local", "git.deploy", "customer:"+c.Username, g.Name+" ok="+strconv.FormatBool(err == nil && res.OK))
		return err
	})
	if err != nil {
		gitBusy.Delete(g.ID)
		return false
	}
	return true
}

func (s *Server) handleGitDeploy(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	g := s.myGit(w, r, c)
	if g == nil {
		return
	}
	back := "/git/" + strconv.FormatInt(g.ID, 10)
	if !s.deployGit(context.WithoutCancel(r.Context()), actor(r), c, g, g.Remote != "") {
		s.redirectErr(w, r, back, "A deployment is running already.")
		return
	}
	s.redirect(w, r, back, "The deployment was started; reload the page in a moment.")
}

func (s *Server) handleGitDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	g := s.myGit(w, r, c)
	if g == nil {
		return
	}
	if r.FormValue("files") != "" {
		if err := s.call(r.Context(), actor(r), "git.delete", map[string]any{"account": c.Username, "repo": gitSpec(g)}, nil); err != nil {
			s.redirectErr(w, r, "/git/"+strconv.FormatInt(g.ID, 10), storeErr(err))
			return
		}
	}
	if err := s.store.DeleteGitRepo(r.Context(), g.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "git.delete", "customer:"+c.Username, "repository %s (files deleted: %v)", g.Name, r.FormValue("files") != "")
	s.redirect(w, r, "/git", "Deleted.")
}

// gitHookLast limits webhook deployments to one per repository every 10 s.
var (
	gitHookMu   sync.Mutex
	gitHookLast = map[int64]time.Time{}
)

func (s *Server) handleGitHook(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	g, err := s.store.GitRepoByToken(r.Context(), tok)
	if err != nil || len(tok) < 20 || subtle.ConstantTimeCompare([]byte(tok), []byte(g.HookToken)) != 1 || g.Remote == "" {
		http.NotFound(w, r)
		return
	}
	c, err := s.store.CustomerByID(r.Context(), g.CustomerID)
	if err != nil || c.Status != store.StatusActive {
		http.NotFound(w, r)
		return
	}
	gitHookMu.Lock()
	recent := time.Since(gitHookLast[g.ID]) < 10*time.Second
	if !recent {
		gitHookLast[g.ID] = time.Now()
	}
	gitHookMu.Unlock()
	if recent || !s.deployGit(context.WithoutCancel(r.Context()), "webhook", c, g, true) {
		http.Error(w, "busy, try again later", http.StatusTooManyRequests)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("deployment started\n"))
}

// maskRemote hides a token in a remote address (https://user:token@host/…).
func maskRemote(u string) string {
	rest, ok := strings.CutPrefix(u, "https://")
	if !ok {
		return u
	}
	host, path, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(host, "@"); i >= 0 {
		return "https://…@" + host[i+1:] + "/" + path
	}
	return u
}

func init() { funcs["maskremote"] = maskRemote }
