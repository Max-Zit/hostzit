package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
)

// E-mail notifications: disk almost full (customer and administrators),
// certificates that cannot be issued, failed automatic WordPress updates
// and failed jobs. Each notice is sent at most once a day.

const settingMail = "mail"

// MailSettings is the SMTP server of the panel.
type MailSettings struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security string   `json:"security"` // starttls, tls, none
	User     string   `json:"user"`
	Password string   `json:"password"` // sealed
	From     string   `json:"from"`
	Admins   []string `json:"admins"`   // addresses of the administrators
	Customer bool     `json:"customer"` // also tell customers about their own account
	// WebRelay: mail from websites also goes through this server.
	WebRelay bool `json:"web_relay"`
	// Off are the kinds of notices nobody wants (see noticeKinds).
	Off []string `json:"off,omitempty"`
}

// Validate checks the settings.
func (m *MailSettings) Validate() error {
	if m.Host == "" {
		return nil // notifications off
	}
	if strings.ContainsAny(m.Host, " /\\@\r\n") || len(m.Host) > 253 {
		return errors.New("the SMTP server is invalid")
	}
	if m.Port < 1 || m.Port > 65535 {
		return errors.New("the SMTP port must be 1–65535")
	}
	if m.Security != "starttls" && m.Security != "tls" && m.Security != "none" {
		return errors.New("choose the connection security")
	}
	if _, err := store.CleanEmail(m.From); err != nil || m.From == "" {
		return errors.New("enter the sender address")
	}
	for i, a := range m.Admins {
		c, err := store.CleanEmail(a)
		if err != nil || c == "" {
			return fmt.Errorf("invalid address %q", a)
		}
		m.Admins[i] = c
	}
	return nil
}

func (s *Server) mailSettings(ctx context.Context) MailSettings {
	var m MailSettings
	_ = s.store.GetSetting(ctx, settingMail, &m)
	return m
}

func header(v string) string { return strings.NewReplacer("\r", "", "\n", "").Replace(v) }

// sendMail sends a plain text message.
func (s *Server) sendMail(ctx context.Context, to []string, subject, body string) error {
	m := s.mailSettings(ctx)
	if m.Host == "" || len(to) == 0 {
		return nil
	}
	pw, _ := s.store.OpenSecret("mail.password", m.Password)
	addr := net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
	d := net.Dialer{Timeout: 20 * time.Second}
	var conn net.Conn
	var err error
	if m.Security == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Minute))
	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()
	if m.Security == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, pw, m.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.From); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: HostZit <" + header(m.From) + ">\r\nTo: " + header(strings.Join(to, ", ")) + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", header(subject)) +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n") + "\r\n"
	if _, err := wc.Write([]byte(msg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// notify sends a notice once per day per key.
func (s *Server) notify(ctx context.Context, key string, c *store.Customer, subject, body string) {
	m := s.mailSettings(ctx)
	if slices.Contains(m.Off, noticeKind(key)) {
		return
	}
	if m.Host == "" || !s.store.NoticeDue(ctx, key, 24*time.Hour) {
		return
	}
	to := append([]string(nil), m.Admins...)
	if c != nil && m.Customer && c.Email != "" {
		to = append(to, c.Email)
	}
	if err := s.sendMail(ctx, to, subject, body); err != nil {
		s.log.Warn("notification not sent", "subject", subject, "err", err)
	}
}

// checkNotices looks for things to tell (called after usage samples).
func (s *Server) checkNotices(ctx context.Context) {
	list, err := s.store.Customers(ctx, store.CustomerFilter{Status: store.StatusActive})
	if err != nil {
		return
	}
	s.checkLimits(ctx, list)
	for _, c := range list {
		p, err := s.store.PackageByID(ctx, c.PackageID)
		if err != nil || p.Limits.DiskMB == 0 {
			continue
		}
		if c.DiskKB*100 >= int64(p.Limits.DiskMB)*1024*90 {
			s.notify(ctx, "disk:"+c.Username, c, "Disk space of "+c.Username+" is almost full",
				fmt.Sprintf("The hosting account %s uses %d MB of %d MB disk space (%d %%).\nDelete old files and backups, or choose a bigger package.\n",
					c.Username, c.DiskKB/1024, p.Limits.DiskMB, c.DiskKB*100/(int64(p.Limits.DiskMB)*1024)))
		}
	}
	sites, _ := s.store.Sites(ctx, 0)
	for _, x := range sites {
		if x.CertStatus == "failed" && x.CertTriedAt != nil && s.now().Sub(x.CreatedAt) > 24*time.Hour {
			c, _ := s.store.CustomerByID(ctx, x.CustomerID)
			s.notify(ctx, "cert:"+x.Domain, c, "No certificate for "+x.Domain, "The website "+x.Domain+" has no HTTPS certificate yet:\n"+x.CertError+"\n\nCheck that the domain points to this server.\n")
		}
		if x.CertStatus == "ok" && x.CertNotAfter != nil && x.CertNotAfter.Sub(s.now()) < 10*24*time.Hour {
			s.notify(ctx, "certexp:"+x.Domain, nil, "Certificate of "+x.Domain+" expires soon", "The certificate of "+x.Domain+" expires on "+x.CertNotAfter.Format("2006-01-02")+" and could not be renewed.\n")
		}
	}
}

// ---- settings page

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /settings/mail", s.handleMailSettings)
		admin("POST /settings/mail", s.handleMailSettingsSave)
		admin("POST /settings/mail/test", s.handleMailTest)
	})
}

type mailData struct {
	M      MailSettings
	Admins string
	HasPW  bool
	Kinds  []noticeChoice
}

func (s *Server) handleMailSettings(w http.ResponseWriter, r *http.Request) {
	m := s.mailSettings(r.Context())
	s.render(w, r, http.StatusOK, "mail", &Page{Title: "Notifications", Nav: "settings", Data: &mailData{M: m, Admins: strings.Join(m.Admins, "\n"), HasPW: m.Password != "", Kinds: noticeChoices(m)}})
}

func (s *Server) handleMailSettingsSave(w http.ResponseWriter, r *http.Request) {
	old := s.mailSettings(r.Context())
	m := MailSettings{Host: strings.TrimSpace(r.FormValue("host")), Port: formInt(r, "port"), Security: r.FormValue("security"), User: strings.TrimSpace(r.FormValue("user")),
		From: strings.TrimSpace(r.FormValue("from")), Admins: netacl.Split(r.FormValue("admins")), Customer: r.FormValue("customer") != "", WebRelay: r.FormValue("web_relay") != "", Password: old.Password}
	for _, k := range noticeKinds {
		if r.FormValue("notice_"+k) == "" {
			m.Off = append(m.Off, k)
		}
	}
	if pw := r.FormValue("password"); pw != "" {
		m.Password = s.store.SealSecret("mail.password", pw)
	}
	if err := m.Validate(); err != nil {
		p := &Page{Title: "Notifications", Nav: "settings", Data: &mailData{M: m, Admins: strings.Join(m.Admins, "\n"), HasPW: m.Password != "", Kinds: noticeChoices(m)}}
		p.Error = translate(s.lang(r, userFrom(r)), err.Error())
		s.render(w, r, http.StatusBadRequest, "mail", p)
		return
	}
	if err := s.store.SetSetting(r.Context(), settingMail, m); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.applyRelay(r.Context(), actor(r)); err != nil {
		s.redirectErr(w, r, "/settings/mail", storeErr(err))
		return
	}
	s.audit(r, "settings.mail", "settings", "SMTP %s:%d (%s), %d administrators", m.Host, m.Port, m.Security, len(m.Admins))
	s.redirect(w, r, "/settings/mail", "Saved.")
}

func (s *Server) handleMailTest(w http.ResponseWriter, r *http.Request) {
	m := s.mailSettings(r.Context())
	to := m.Admins
	if u := userFrom(r); u.Email != "" {
		to = []string{u.Email}
	}
	if len(to) == 0 {
		s.redirectErr(w, r, "/settings/mail", "Enter at least one administrator address.")
		return
	}
	if err := s.sendMail(r.Context(), to, "HostZit test message", "This is a test message from the HostZit panel. Notifications work.\n"); err != nil {
		s.redirectErr(w, r, "/settings/mail", err.Error())
		return
	}
	s.redirect(w, r, "/settings/mail", translate(s.lang(r, userFrom(r)), "A test message was sent to %s.", strings.Join(to, ", ")))
}

// applyRelay tells the helper where mail from websites goes.
func (s *Server) applyRelay(ctx context.Context, by string) error {
	m := s.mailSettings(ctx)
	relay := map[string]any{"host": "", "port": 0}
	if m.WebRelay && m.Host != "" {
		pw, _ := s.store.OpenSecret("mail.password", m.Password)
		dom := s.hostingSettings(ctx).ServerName
		relay = map[string]any{"host": m.Host, "port": m.Port, "security": m.Security, "user": m.User, "password": pw, "domain": dom}
	}
	return s.call(ctx, by, "mail.relay", map[string]any{"relay": relay}, nil)
}

// noticeKinds can be switched off one by one in the settings.
var noticeKinds = []string{"disk", "cert", "malware", "limits", "backup", "wordpress", "server", "updates", "approval"}

// noticeKind maps a notice key ("disk:shop1", "remote-backup" …) to its kind.
func noticeKind(key string) string {
	k, _, _ := strings.Cut(key, ":")
	switch k {
	case "certexp":
		return "cert"
	case "remote-backup", "panel-backup":
		return "backup"
	case "wp":
		return "wordpress"
	case "service", "serverdisk", "reboot":
		return "server"
	case "security-updates":
		return "updates"
	}
	return k
}

// checkLimits tells customers (and the administrators) whose account was
// held back by its package limits for an hour or more in the last day.
func (s *Server) checkLimits(ctx context.Context, list []*store.Customer) {
	all, err := s.store.UsageAll(ctx, s.now().Add(-24*time.Hour))
	if err != nil {
		return
	}
	for _, c := range list {
		hits := 0
		for _, r := range store.Rates(all[c.ID]) {
			if r.LimitHit() {
				hits++
			}
		}
		if hits >= 6 {
			s.notify(ctx, "limits:"+c.Username, c, "Hosting account "+c.Username+" reaches its limits",
				fmt.Sprintf("In the last 24 hours the package limits held the hosting account %s back for about %d minutes: the CPU limit slowed it down or the memory limit ended processes.\n\nThe panel shows when under Usage → Limits reached. Often a plugin, a crawler or an attack is the cause; if it happens every day, a bigger package helps.\n", c.Username, hits*10))
		}
	}
}

// checkServer looks at the server itself (hourly): services, disks, a
// pending restart and waiting security updates.
func (s *Server) checkServer(ctx context.Context) {
	if in, err := s.serverInfo(ctx); err == nil {
		for _, name := range []string{"nginx", "mariadb", "postgresql", "pdns", "ssh"} {
			st, ok := in.Services[name]
			if !ok || st == "active" || st == "activating" || st == "reloading" {
				continue
			}
			if v, known := in.Programs[name]; known && v == "" {
				continue // not installed
			}
			s.notify(ctx, "service:"+name, nil, "Service "+name+" is not running", "The service "+name+" on this HostZit server is "+st+".\nSee Server in the admin panel; websites, mail or DNS may be affected.\n")
		}
		for _, d := range in.Disks {
			if d.SizeMB > 0 && d.UsedMB*100 >= d.SizeMB*90 {
				s.notify(ctx, "serverdisk:"+d.Mount, nil, "Disk "+d.Mount+" of the server is almost full",
					fmt.Sprintf("The file system %s uses %d of %d MB (%d %%).\n", d.Mount, d.UsedMB, d.SizeMB, d.UsedMB*100/d.SizeMB))
			}
		}
	}
	var st helper.OSStatus
	if err := s.call(ctx, "system", "os.status", map[string]bool{"refresh": false}, &st); err != nil {
		return
	}
	if st.RebootRequired {
		s.notify(ctx, "reboot", nil, "The server needs a restart", "Updated system parts (e.g. the kernel) are used only after a restart of the server: "+strings.Join(st.RebootPackages, " ")+"\nRestart it at a quiet time.\n")
	}
	sec := 0
	for _, p := range st.Packages {
		if p.Security {
			sec++
		}
	}
	if sec > 0 && !st.Auto && !st.Running {
		s.notify(ctx, "security-updates", nil, fmt.Sprintf("%d security updates wait", sec),
			fmt.Sprintf("%d security updates of the operating system wait on this HostZit server. Install them under Settings → System, or switch the nightly security updates on there.\n", sec))
	}
}

type noticeChoice struct {
	Key, Label string
	On         bool
}

var noticeLabels = map[string]string{
	"disk": "Disk space of an account almost full", "cert": "Certificates not issued or not renewed", "malware": "Malware found",
	"limits": "Accounts held back by their limits", "backup": "Failed backups (remote and panel)", "wordpress": "Failed automatic WordPress updates",
	"server": "Services down, server disk almost full, restart needed", "updates": "Waiting security updates", "approval": "Approvals needed (four-eyes)",
}

func noticeChoices(m MailSettings) []noticeChoice {
	out := make([]noticeChoice, 0, len(noticeKinds))
	for _, k := range noticeKinds {
		out = append(out, noticeChoice{Key: k, Label: noticeLabels[k], On: !slices.Contains(m.Off, k)})
	}
	return out
}
