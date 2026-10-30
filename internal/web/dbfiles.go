package web

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// ---- databases

type dbData struct {
	C      *store.Customer
	DBs    []*store.Database
	Users  []*store.DBUser
	Max    int
	NewPW  string
	NewFor string
}

func (s *Server) showDatabases(w http.ResponseWriter, r *http.Request, c *store.Customer, d *dbData) {
	var err error
	if d.DBs, err = s.store.Databases(r.Context(), c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.Users, err = s.store.DBUsers(r.Context(), c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if p, err := s.store.PackageByID(r.Context(), c.PackageID); err == nil {
		d.Max = p.MaxDBs
	}
	d.C = c
	s.render(w, r, http.StatusOK, "databases", &Page{Title: "Databases", Nav: "databases", Customer: c, Data: d})
}

func (s *Server) handleDatabases(w http.ResponseWriter, r *http.Request) {
	if c := s.me(w, r); c != nil {
		s.showDatabases(w, r, c, &dbData{})
	}
}

// handleDatabaseCreate makes a database and, by default, a user of the
// same name with a generated password (shown once), like cPanel's wizard.
func (s *Server) handleDatabaseCreate(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	name, err := hosting.DatabaseName(c.Username, r.FormValue("name"))
	if err != nil {
		s.redirectErr(w, r, "/databases", err.Error())
		return
	}
	p, _ := s.store.PackageByID(r.Context(), c.PackageID)
	_, dbs, _, _ := s.store.CountFor(r.Context(), c.ID)
	if p != nil && s.hostingSettings(r.Context()).Mode != "dedicated" && dbs >= p.MaxDBs {
		s.redirectErr(w, r, "/databases", translate(s.lang(r, userFrom(r)), "The package allows %d databases.", p.MaxDBs))
		return
	}
	if err := s.store.AddDatabase(r.Context(), c.ID, name); err != nil {
		s.redirectErr(w, r, "/databases", storeErr(err))
		return
	}
	if err := s.call(r.Context(), actor(r), "db.create", map[string]string{"account": c.Username, "name": name}, nil); err != nil {
		_ = s.store.DeleteDatabase(r.Context(), c.ID, name)
		s.redirectErr(w, r, "/databases", storeErr(err))
		return
	}
	s.audit(r, "db.create", "db:"+name, "")
	d := &dbData{}
	if r.FormValue("with_user") != "" {
		pw := auth.RandomToken(18)
		if err := s.call(r.Context(), actor(r), "db.user", map[string]any{"account": c.Username, "user": name, "password": pw, "databases": []string{name}}, nil); err != nil {
			s.redirectErr(w, r, "/databases", storeErr(err))
			return
		}
		_ = s.store.SaveDBUser(r.Context(), c.ID, name, []string{name})
		s.audit(r, "db.user.save", "dbuser:"+name, "created with access to %s", name)
		d.NewPW, d.NewFor = pw, name
	}
	s.showDatabases(w, r, c, d)
}

func (s *Server) handleDatabaseDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	name := r.PathValue("name")
	if !hosting.ValidDatabase(c.Username, name) {
		s.notFound(w, r)
		return
	}
	if r.FormValue("confirm") != name {
		s.redirectErr(w, r, "/databases", "Type the database name to confirm.")
		return
	}
	if err := s.call(r.Context(), actor(r), "db.drop", map[string]string{"account": c.Username, "name": name}, nil); err != nil {
		s.redirectErr(w, r, "/databases", storeErr(err))
		return
	}
	_ = s.store.DeleteDatabase(r.Context(), c.ID, name)
	s.resyncDBUsers(r, c)
	s.audit(r, "db.drop", "db:"+name, "")
	s.redirect(w, r, "/databases", "The database was deleted.")
}

// resyncDBUsers applies the grants of all users again (after a database is gone).
func (s *Server) resyncDBUsers(r *http.Request, c *store.Customer) {
	users, _ := s.store.DBUsers(r.Context(), c.ID)
	for _, u := range users {
		_ = s.call(r.Context(), actor(r), "db.user", map[string]any{"account": c.Username, "user": u.Name, "databases": u.Databases}, nil)
	}
}

func (s *Server) handleDBUserSave(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	name, err := hosting.DatabaseName(c.Username, r.FormValue("user"))
	if err != nil {
		s.redirectErr(w, r, "/databases", err.Error())
		return
	}
	own, _ := s.store.Databases(r.Context(), c.ID)
	var grant []string
	for _, d := range own {
		if r.FormValue("db_"+d.Name) != "" {
			grant = append(grant, d.Name)
		}
	}
	pw := r.FormValue("password")
	gen := false
	if pw == "" && r.FormValue("generate") != "" {
		pw, gen = auth.RandomToken(18), true
	}
	if err := s.call(r.Context(), actor(r), "db.user", map[string]any{"account": c.Username, "user": name, "password": pw, "databases": grant}, nil); err != nil {
		s.redirectErr(w, r, "/databases", storeErr(err))
		return
	}
	if err := s.store.SaveDBUser(r.Context(), c.ID, name, grant); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "db.user.save", "dbuser:"+name, "access to %s", strings.Join(grant, ", "))
	if gen {
		s.showDatabases(w, r, c, &dbData{NewPW: pw, NewFor: name})
		return
	}
	s.redirect(w, r, "/databases", "Saved.")
}

func (s *Server) handleDBUserDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	name := r.PathValue("name")
	if !hosting.ValidDatabase(c.Username, name) {
		s.notFound(w, r)
		return
	}
	if err := s.call(r.Context(), actor(r), "db.user.drop", map[string]string{"account": c.Username, "user": name}, nil); err != nil {
		s.redirectErr(w, r, "/databases", storeErr(err))
		return
	}
	_ = s.store.DeleteDBUser(r.Context(), c.ID, name)
	s.audit(r, "db.user.drop", "dbuser:"+name, "")
	s.redirect(w, r, "/databases", "The database user was deleted.")
}

// ---- file manager

func (s *Server) worker(r *http.Request, c *store.Customer, req helper.WorkerReq) (helper.WorkerResp, error) {
	var resp helper.WorkerResp
	err := s.call(r.Context(), actor(r), "files", map[string]any{"account": c.Username, "req": req}, &resp)
	return resp, err
}

type crumb struct{ Name, Path string }

type filesData struct {
	Path   string
	Crumbs []crumb
	Files  []helper.FileInfo
	Err    string
}

func crumbsOf(p string) []crumb {
	out := []crumb{{Name: "~", Path: ""}}
	acc := ""
	for _, part := range strings.Split(p, "/") {
		if part == "" {
			continue
		}
		acc = strings.TrimPrefix(acc+"/"+part, "/")
		out = append(out, crumb{Name: part, Path: acc})
	}
	return out
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	p, err := hosting.CleanRelPath(r.FormValue("path"))
	d := &filesData{Path: p, Crumbs: crumbsOf(p)}
	if err != nil {
		d.Err = err.Error()
	} else if resp, err := s.worker(r, c, helper.WorkerReq{Op: "list", Path: p}); err != nil {
		d.Err = storeErr(err)
	} else {
		d.Files = resp.Files
	}
	s.render(w, r, http.StatusOK, "files", &Page{Title: "Files", Nav: "files", Customer: c, Data: d})
}

func filesURL(p string) string { return "/files?path=" + url.QueryEscape(p) }

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	p, err := hosting.CleanRelPath(r.FormValue("path"))
	if err != nil || p == "" {
		s.notFound(w, r)
		return
	}
	resp, err := s.worker(r, c, helper.WorkerReq{Op: "read", Path: p})
	if err != nil {
		s.redirectErr(w, r, filesURL(path.Dir(p)), storeErr(err))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(p)}))
	w.Header().Set("Content-Length", strconv.Itoa(len(resp.Data)))
	_, _ = w.Write(resp.Data)
}

// handleFileAction: upload, new folder, rename, delete, permissions.
func (s *Server) handleFileAction(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, helper.MaxFileData+1<<20)
	dir, err := hosting.CleanRelPath(r.FormValue("dir"))
	if err != nil {
		s.redirectErr(w, r, "/files", err.Error())
		return
	}
	back := filesURL(dir)
	join := func(name string) (string, error) {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "/\\") {
			return "", errors.New("enter a name without /")
		}
		return hosting.CleanRelPath(dir + "/" + name)
	}
	var req helper.WorkerReq
	var what string
	switch r.FormValue("action") {
	case "upload":
		f, hdr, err := r.FormFile("file")
		if err != nil {
			s.redirectErr(w, r, back, "Choose a file (up to 48 MB; use SFTP for larger files).")
			return
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, helper.MaxFileData+1))
		if err != nil || len(data) > helper.MaxFileData {
			s.redirectErr(w, r, back, "The file is too large; use SFTP.")
			return
		}
		p, err := join(path.Base(strings.ReplaceAll(hdr.Filename, "\\", "/")))
		if err != nil {
			s.redirectErr(w, r, back, err.Error())
			return
		}
		req, what = helper.WorkerReq{Op: "write", Path: p, Data: data}, "upload "+p
	case "mkdir":
		p, err := join(r.FormValue("name"))
		if err != nil {
			s.redirectErr(w, r, back, err.Error())
			return
		}
		req, what = helper.WorkerReq{Op: "mkdir", Path: p}, "new folder "+p
	case "newfile":
		p, err := join(r.FormValue("name"))
		if err != nil {
			s.redirectErr(w, r, back, err.Error())
			return
		}
		req, what = helper.WorkerReq{Op: "write", Path: p, Data: []byte{}}, "new file "+p
	case "rename":
		from, err1 := join(r.FormValue("name"))
		to, err2 := join(r.FormValue("to"))
		if err1 != nil || err2 != nil {
			s.redirectErr(w, r, back, "Invalid name.")
			return
		}
		req, what = helper.WorkerReq{Op: "rename", Path: from, To: to}, "rename "+from+" → "+to
	case "delete":
		p, err := join(r.FormValue("name"))
		if err != nil {
			s.redirectErr(w, r, back, err.Error())
			return
		}
		req, what = helper.WorkerReq{Op: "delete", Path: p}, "delete "+p
	case "chmod":
		p, err := join(r.FormValue("name"))
		if err != nil {
			s.redirectErr(w, r, back, err.Error())
			return
		}
		req, what = helper.WorkerReq{Op: "chmod", Path: p, Mode: strings.TrimSpace(r.FormValue("mode"))}, "permissions "+p+" "+r.FormValue("mode")
	default:
		s.redirectErr(w, r, back, "Unknown action.")
		return
	}
	if _, err := s.worker(r, c, req); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "files", "customer:"+c.Username, "%s", what)
	s.redirect(w, r, back, "Done.")
}

type editData struct {
	Path   string
	Dir    string
	Text   string
	Binary bool
}

const maxEdit = 2 << 20

func (s *Server) handleFileEdit(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	p, err := hosting.CleanRelPath(r.FormValue("path"))
	if err != nil || p == "" {
		s.notFound(w, r)
		return
	}
	resp, err := s.worker(r, c, helper.WorkerReq{Op: "read", Path: p, Limit: maxEdit})
	if err != nil {
		s.redirectErr(w, r, filesURL(path.Dir(p)), storeErr(err))
		return
	}
	d := &editData{Path: p, Dir: strings.TrimPrefix(path.Dir("/"+p), "/"), Text: string(resp.Data), Binary: !utf8.Valid(resp.Data)}
	s.render(w, r, http.StatusOK, "fileedit", &Page{Title: path.Base(p), Nav: "files", Customer: c, Crumb: "Files", CrumbURL: filesURL(d.Dir), Data: d})
}

func (s *Server) handleFileSave(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxEdit*2)
	p, err := hosting.CleanRelPath(r.FormValue("path"))
	if err != nil || p == "" {
		s.notFound(w, r)
		return
	}
	text := strings.ReplaceAll(r.FormValue("text"), "\r\n", "\n")
	if _, err := s.worker(r, c, helper.WorkerReq{Op: "write", Path: p, Data: []byte(text)}); err != nil {
		s.redirectErr(w, r, "/files/edit?path="+url.QueryEscape(p), storeErr(err))
		return
	}
	s.audit(r, "files", "customer:"+c.Username, "edit %s (%d bytes)", p, len(text))
	s.redirect(w, r, "/files/edit?path="+url.QueryEscape(p), "Saved.")
}

