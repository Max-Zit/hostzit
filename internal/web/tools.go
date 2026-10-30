package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// Scheduled jobs (cron) and SSH keys of customers.

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("GET /cron", s.handleCron)
		c("POST /cron", s.handleCronAdd)
		c("POST /cron/{id}/toggle", s.handleCronToggle)
		c("POST /cron/{id}/run", s.handleCronRun)
		c("POST /cron/{id}/delete", s.handleCronDelete)
		c("GET /cron/{id}/log", s.handleCronLog)
		c("POST /access/keys", s.handleKeyAdd)
		c("POST /access/keys/{id}/delete", s.handleKeyDelete)
	})
}

type cronData struct {
	Jobs []*store.CronJob
	Next map[int64]string
	F    map[string]string
}

func (s *Server) applyCron(ctx context.Context, by string, c *store.Customer) error {
	jobs, err := s.store.CronJobs(ctx, c.ID)
	if err != nil {
		return err
	}
	list := []hosting.CronJob{}
	for _, j := range jobs {
		list = append(list, hosting.CronJob{ID: j.ID, Schedule: j.Schedule, Command: j.Command, Enabled: j.Enabled && c.Status == store.StatusActive})
	}
	return s.call(ctx, by, "cron.apply", map[string]any{"account": c.Username, "jobs": list}, nil)
}

func (s *Server) handleCron(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	jobs, err := s.store.CronJobs(r.Context(), c.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &cronData{Jobs: jobs, Next: map[int64]string{}, F: map[string]string{"schedule": "*/15 * * * *"}}
	for _, j := range jobs {
		d.Next[j.ID], _ = hosting.OnCalendar(j.Schedule)
	}
	s.render(w, r, http.StatusOK, "cron", &Page{Title: "Scheduled jobs", Nav: "cron", Customer: c, Data: d})
}

func (s *Server) handleCronAdd(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	j := &store.CronJob{CustomerID: c.ID, Schedule: strings.TrimSpace(r.FormValue("schedule")), Command: strings.TrimSpace(r.FormValue("command")), Enabled: true, Note: r.FormValue("note")}
	if _, err := hosting.OnCalendar(j.Schedule); err != nil {
		s.redirectErr(w, r, "/cron", err.Error())
		return
	}
	if err := hosting.CheckCommand(j.Command); err != nil {
		s.redirectErr(w, r, "/cron", err.Error())
		return
	}
	if err := s.store.AddCronJob(r.Context(), j); err != nil {
		s.redirectErr(w, r, "/cron", storeErr(err))
		return
	}
	if err := s.applyCron(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, "/cron", storeErr(err))
		return
	}
	s.audit(r, "cron.add", "customer:"+c.Username, "%s %s", j.Schedule, j.Command)
	s.redirect(w, r, "/cron", "The job was added.")
}

func (s *Server) cronID(w http.ResponseWriter, r *http.Request, c *store.Customer) (int64, bool) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return 0, false
	}
	jobs, _ := s.store.CronJobs(r.Context(), c.ID)
	for _, j := range jobs {
		if j.ID == id {
			return id, true
		}
	}
	s.notFound(w, r)
	return 0, false
}

func (s *Server) handleCronToggle(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	id, ok := s.cronID(w, r, c)
	if !ok {
		return
	}
	on := r.FormValue("on") != ""
	_ = s.store.SetCronEnabled(r.Context(), c.ID, id, on)
	if err := s.applyCron(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, "/cron", storeErr(err))
		return
	}
	s.audit(r, "cron.toggle", "customer:"+c.Username, "job %d on: %v", id, on)
	s.redirect(w, r, "/cron", "Saved.")
}

func (s *Server) handleCronRun(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	id, ok := s.cronID(w, r, c)
	if !ok {
		return
	}
	if err := s.call(r.Context(), actor(r), "cron.run", map[string]any{"account": c.Username, "id": id}, nil); err != nil {
		s.redirectErr(w, r, "/cron", storeErr(err))
		return
	}
	s.redirect(w, r, "/cron/"+strconv.FormatInt(id, 10)+"/log", "The job was started.")
}

func (s *Server) handleCronDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	id, ok := s.cronID(w, r, c)
	if !ok {
		return
	}
	_ = s.store.DeleteCronJob(r.Context(), c.ID, id)
	if err := s.applyCron(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, "/cron", storeErr(err))
		return
	}
	s.audit(r, "cron.delete", "customer:"+c.Username, "job %d deleted", id)
	s.redirect(w, r, "/cron", "The job was deleted.")
}

func (s *Server) handleCronLog(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	id, ok := s.cronID(w, r, c)
	if !ok {
		return
	}
	var res struct {
		Text string `json:"text"`
	}
	if err := s.call(r.Context(), actor(r), "cron.log", map[string]any{"account": c.Username, "id": id}, &res); err != nil {
		res.Text = storeErr(err)
	}
	s.render(w, r, http.StatusOK, "cronlog", &Page{Title: "Job output", Nav: "cron", Customer: c, Crumb: "Scheduled jobs", CrumbURL: "/cron", Data: res.Text})
}

// ---- SSH keys

func (s *Server) applyKeys(r *http.Request, c *store.Customer) error {
	keys, err := s.store.SSHKeys(r.Context(), c.ID)
	if err != nil {
		return err
	}
	list := []string{}
	for _, k := range keys {
		list = append(list, k.Key)
	}
	return s.call(r.Context(), actor(r), "ssh.keys", map[string]any{"account": c.Username, "keys": list}, nil)
}

func (s *Server) handleKeyAdd(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	line, fp, err := helper.CheckSSHKey(r.FormValue("key"))
	if err != nil {
		s.redirectErr(w, r, "/access", err.Error())
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = fp[len(fp)-8:]
	}
	if err := s.store.AddSSHKey(r.Context(), &store.SSHKey{CustomerID: c.ID, Name: name, Key: line, Fingerprint: fp}); err != nil {
		s.redirectErr(w, r, "/access", storeErr(err))
		return
	}
	if err := s.applyKeys(r, c); err != nil {
		s.redirectErr(w, r, "/access", storeErr(err))
		return
	}
	s.audit(r, "ssh.key.add", "customer:"+c.Username, "key %s (%s)", name, fp)
	s.redirect(w, r, "/access", "The SSH key was added.")
}

func (s *Server) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	id, _ := pathID(r, "id")
	if err := s.store.DeleteSSHKey(r.Context(), c.ID, id); err != nil {
		s.notFound(w, r)
		return
	}
	if err := s.applyKeys(r, c); err != nil {
		s.redirectErr(w, r, "/access", storeErr(err))
		return
	}
	s.audit(r, "ssh.key.delete", "customer:"+c.Username, "key %d removed", id)
	s.redirect(w, r, "/access", "The SSH key was removed.")
}
