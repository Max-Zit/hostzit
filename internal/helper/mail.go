package helper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Mail from websites. Account processes cannot reach SMTP ports (the
// firewall rejects 25/465/587 for hosting uids), so PHP's mail() goes to
// "hostzit-helper sendmail": it runs as the account inside its cage and
// puts the message into the account's spool (/.spool in the cage). The
// helper picks the spool up, keeps the hourly limit of the account's
// package and sends the messages: itself (maildirect.go), through
// EmailZit's relay login of the link, or through the administrator's relay.

// SpoolRoot holds one folder per account.
const SpoolRoot = "/var/spool/hostzit"

// MaxMessage is the largest message a website may send.
const MaxMessage = 10 << 20

// queued is the envelope stored next to a message.
type queued struct {
	Account string    `json:"account,omitempty"`
	Args    []string  `json:"args"`
	From    string    `json:"from,omitempty"` // -f
	To      []string  `json:"to"`
	At      time.Time `json:"at"`
	Tries   int       `json:"tries,omitempty"`
	LastErr string    `json:"last_error,omitempty"`
	NextTry time.Time `json:"next_try,omitempty"`
	Subject string    `json:"subject,omitempty"`
}

// RunSendmail is the sendmail replacement (inside the cage, as the account).
func RunSendmail(spool string, args []string, in io.Reader) error {
	q := queued{Args: args, At: time.Now().UTC()}
	readTo := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t":
			readTo = true
		case a == "-f" && i+1 < len(args):
			q.From = args[i+1]
			i++
		case strings.HasPrefix(a, "-f") && len(a) > 2:
			q.From = a[2:]
		case a == "-i" || a == "-oi" || strings.HasPrefix(a, "-o") || a == "--":
		case strings.HasPrefix(a, "-"):
		default:
			q.To = append(q.To, a)
		}
	}
	msg, err := io.ReadAll(io.LimitReader(in, MaxMessage+1))
	if err != nil {
		return err
	}
	if len(msg) > MaxMessage {
		return errors.New("sendmail: the message is larger than 10 MB")
	}
	m, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return fmt.Errorf("sendmail: the message has no valid headers: %w", err)
	}
	if readTo {
		for _, h := range []string{"To", "Cc", "Bcc"} {
			if l, err := m.Header.AddressList(h); err == nil {
				for _, a := range l {
					q.To = append(q.To, a.Address)
				}
			}
		}
	}
	q.Subject = m.Header.Get("Subject")
	if len(q.To) == 0 {
		return errors.New("sendmail: no recipients")
	}
	if len(q.To) > 50 {
		return errors.New("sendmail: at most 50 recipients per message")
	}
	var rb [6]byte
	_, _ = rand.Read(rb[:])
	id := strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + hex.EncodeToString(rb[:])
	tmp := filepath.Join(spool, "."+id)
	if err := os.WriteFile(tmp+".eml", msg, 0o600); err != nil {
		return fmt.Errorf("sendmail: %w", err)
	}
	if err := os.Rename(tmp+".eml", filepath.Join(spool, id+".eml")); err != nil {
		return err
	}
	env, _ := json.Marshal(q)
	if err := os.WriteFile(tmp+".json", env, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp+".json", filepath.Join(spool, id+".json"))
}

// RelayConfig is where mail from websites goes.
type RelayConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"` // starttls, tls, none
	User     string `json:"user"`
	Password string `json:"password"`
	Domain   string `json:"domain"` // envelope senders: <account>@<domain>
	// Mode: direct (HostZit delivers), emailzit (EmailZit's relay login of
	// the link) or relay (the administrator's SMTP server); "" = relay
	// with a host, else direct.
	Mode string `json:"mode,omitempty"`
	// Helo is the server name the mailer introduces itself with.
	Helo string `json:"helo,omitempty"`
	// ID names an EmailZit link (its relay login); "" for the others.
	ID string `json:"id,omitempty"`
	// Relays are the relay logins of the linked EmailZit servers by link
	// id: an account whose mail is on one of them sends through it (its
	// MailAccount.Relay), the others take the route above.
	Relays map[string]RelayConfig `json:"relays,omitempty"`
}

const relayFile = "/etc/hostzit/mail-relay.json"
const accountsDir = "/etc/hostzit/accounts" // <account>.json: limits the mailer needs

type relayArgs struct {
	Relay RelayConfig `json:"relay"`
}

func (h *Helper) mailRelay(_ context.Context, a relayArgs) (any, error) {
	r := a.Relay
	if r.Host != "" && (strings.ContainsAny(r.Host, " /\\@\r\n") || r.Port < 1 || r.Port > 65535) {
		return nil, userErr("invalid relay server")
	}
	if r.Domain != "" && !hosting.ValidDomain(r.Domain) {
		return nil, userErr("invalid sender domain")
	}
	if r.Mode != "" && r.Mode != "direct" && r.Mode != "relay" && r.Mode != "emailzit" {
		return nil, userErr("invalid mail mode")
	}
	if r.Helo != "" && !hosting.ValidDomain(r.Helo) {
		return nil, userErr("invalid server name")
	}
	if len(r.Relays) > 100 {
		return nil, userErr("too many relays")
	}
	for id, x := range r.Relays {
		if !selectorRE(id) || x.Host == "" || strings.ContainsAny(x.Host, " /\\@\r\n") || x.Port < 1 || x.Port > 65535 || len(x.Relays) > 0 {
			return nil, userErr("invalid relay of a link")
		}
	}
	b, _ := json.Marshal(r) // #nosec G117 -- the relay password goes into a root-only file (0600) of the helper
	return nil, h.Sys.WriteFile(relayFile, b, 0o600, 0, 0)
}

type mailQueueArgs struct {
	Account string `json:"account"`
}

// QueueItem is a waiting message.
type QueueItem struct {
	ID      string    `json:"id"`
	To      []string  `json:"to"`
	Subject string    `json:"subject"`
	At      time.Time `json:"at"`
	Tries   int       `json:"tries"`
	LastErr string    `json:"last_error"`
}

func (h *Helper) mailQueue(_ context.Context, a mailQueueArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	dir := SpoolRoot + "/" + a.Account
	ents, _ := h.Sys.ReadDir(dir)
	out := []QueueItem{}
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, ".json") || strings.HasPrefix(n, ".") {
			continue
		}
		b, err := h.Sys.ReadFile(dir + "/" + n)
		if err != nil {
			continue
		}
		var q queued
		if json.Unmarshal(b, &q) == nil {
			out = append(out, QueueItem{ID: strings.TrimSuffix(n, ".json"), To: q.To, Subject: q.Subject, At: q.At, Tries: q.Tries, LastErr: q.LastErr})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// mailer delivers the spools (started by the helper's serve mode).
type mailer struct {
	h    *Helper
	mu   sync.Mutex
	sent map[string][]time.Time // account → send times in the last hour
}

// RunMailer delivers queued mail until ctx ends.
func (h *Helper) RunMailer(ctx context.Context) {
	m := &mailer{h: h, sent: map[string][]time.Time{}}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.round(ctx)
		}
	}
}

func (m *mailer) limit(account string) int {
	b, err := m.h.Sys.ReadFile(accountsDir + "/" + account + ".json")
	if err != nil {
		return 0
	}
	var a hosting.Account
	if json.Unmarshal(b, &a) != nil || a.Suspended {
		return 0
	}
	return a.Limits.MailPerHour
}

// mode is how website mail leaves: "direct" (HostZit delivers it itself),
// "emailzit" (EmailZit's relay login of the link) or "relay" (the SMTP
// server the administrator set).
func (r RelayConfig) mode() string {
	switch {
	case r.Mode == "emailzit" || r.Mode == "relay" || r.Mode == "direct":
		return r.Mode
	case r.Host != "":
		return "relay"
	}
	return "direct"
}

func (m *mailer) round(ctx context.Context) {
	b, err := m.h.Sys.ReadFile(relayFile)
	var relay RelayConfig
	if err == nil {
		_ = json.Unmarshal(b, &relay)
	}
	if relay.mode() != "direct" && relay.Host == "" {
		relay = RelayConfig{Mode: "direct", Helo: relay.Helo}
	}
	accounts, _ := m.h.Sys.ReadDir(SpoolRoot)
	now := time.Now()
	for _, acc := range accounts {
		name := acc.Name()
		if hosting.ValidAccount(name) != nil {
			continue
		}
		dir := SpoolRoot + "/" + name
		ents, _ := m.h.Sys.ReadDir(dir)
		var ids []string
		for _, e := range ents {
			if n := e.Name(); strings.HasSuffix(n, ".json") && !strings.HasPrefix(n, ".") {
				ids = append(ids, strings.TrimSuffix(n, ".json"))
			}
		}
		sort.Strings(ids)
		limit := m.limit(name)
		for _, id := range ids {
			if ctx.Err() != nil {
				return
			}
			m.mu.Lock()
			recent := m.sent[name][:0]
			for _, t := range m.sent[name] {
				if now.Sub(t) < time.Hour {
					recent = append(recent, t)
				}
			}
			m.sent[name] = recent
			over := len(recent) >= limit
			m.mu.Unlock()
			if over {
				break // the rest waits for the next hour
			}
			m.deliver(ctx, relay, name, dir, id)
		}
	}
}

func (m *mailer) deliver(ctx context.Context, relay RelayConfig, account, dir, id string) {
	envFile, emlFile := dir+"/"+id+".json", dir+"/"+id+".eml"
	b, err := m.h.Sys.ReadFile(envFile)
	if err != nil {
		return
	}
	var q queued
	if json.Unmarshal(b, &q) != nil {
		_ = m.h.Sys.Remove(envFile)
		return
	}
	if !q.NextTry.IsZero() && time.Now().Before(q.NextTry) {
		return
	}
	msg, err := m.h.Sys.ReadFile(emlFile)
	if err != nil {
		_ = m.h.Sys.Remove(envFile)
		return
	}
	// the route: the relay of the account's EmailZit, else the server's own
	ma, known := m.account(account)
	if known && ma.Relay != "" {
		r, ok := relay.Relays[ma.Relay]
		if !ok {
			// the relay of the account's EmailZit is not there (its login
			// could not be read): wait rather than send another way
			if time.Since(q.At) < 48*time.Hour {
				q.NextTry = time.Now().Add(5 * time.Minute)
				q.LastErr = "waiting for the relay of the account's EmailZit"
				nb, _ := json.Marshal(q)
				_ = m.h.Sys.WriteFile(envFile, nb, 0o600, 0, 0)
				m.h.logf("mail from %s waits: no relay for EmailZit link %s", account, ma.Relay)
				return
			}
		} else {
			r.Mode, r.ID, r.Helo = "emailzit", ma.Relay, relay.Helo
			relay = r
		}
	}
	mode := relay.mode()
	entry := MailLogEntry{At: time.Now().UTC(), ID: id, To: q.To, Subject: q.Subject, Via: mode}
	done := func(e MailLogEntry) {
		_ = m.h.Sys.Remove(envFile)
		_ = m.h.Sys.Remove(emlFile)
		m.h.recordMail(account, e)
	}
	count := func() {
		m.mu.Lock()
		m.sent[account] = append(m.sent[account], time.Now())
		m.mu.Unlock()
	}
	var res rcptResult
	switch mode {
	case "relay":
		err = sendVia(ctx, relay, account, "", q, stripBcc(msg))
		m.h.relayState("smarthost", err)
		res = wholeResult(q.To, err)
		if err == nil {
			res.Host = relay.Host
		}
	default:
		if !known {
			// found on h1: right after the update the queued messages were
			// refused because the panel had not sent the domains yet
			if time.Since(q.At) < 48*time.Hour {
				q.NextTry = time.Now().Add(time.Minute)
				q.LastErr = "waiting for the domains of the account from the panel"
				nb, _ := json.Marshal(q)
				_ = m.h.Sys.WriteFile(envFile, nb, 0o600, 0, 0)
				return
			}
		}
		// signed with the domain's hz1 key also through EmailZit's relay:
		// EmailZit signs only its own mail domains, and a domain that is only
		// a website here would leave unsigned (EmailZit, INTEGRATION.md 7)
		p := prepare(account, ma, q, msg, true, time.Now())
		entry.From = p.Header
		if p.Refusal != "" {
			entry.Status, entry.Detail = "refused", p.Refusal
			done(entry)
			m.h.logf("mail from %s refused: %s", account, p.Refusal)
			return
		}
		if mode == "emailzit" {
			err = sendVia(ctx, relay, account, p.From, q, p.Msg)
			m.h.relayState(relay.ID, err)
			res = wholeResult(q.To, err)
			if err == nil {
				res.Host = relay.Host
			}
		} else {
			res = deliverDirect(ctx, helloName(relay.Helo), p.From, q.To, p.Msg)
		}
	}
	if len(res.Sent) > 0 {
		count()
		e := entry
		e.To, e.Status, e.Detail = res.Sent, "sent", res.Host
		m.h.recordMail(account, e)
	}
	for r, why := range res.Bounced {
		e := entry
		e.To, e.Status, e.Detail = []string{r}, "bounced", why
		m.h.recordMail(account, e)
	}
	if len(res.Deferred) == 0 {
		_ = m.h.Sys.Remove(envFile)
		_ = m.h.Sys.Remove(emlFile)
		m.h.logf("mail from %s: %d sent, %d refused by the receiver", account, len(res.Sent), len(res.Bounced))
		return
	}
	var left []string
	var last string
	for _, r := range q.To {
		if why, ok := res.Deferred[r]; ok {
			left = append(left, r)
			last = why
		}
	}
	q.To = left
	q.Tries++
	q.LastErr = last
	q.NextTry = time.Now().Add(time.Duration(q.Tries*q.Tries) * time.Minute)
	if time.Since(q.At) > 48*time.Hour {
		e := entry
		e.To, e.Status, e.Detail = left, "failed", "not delivered in 48 hours: "+last
		done(e)
		m.h.logf("mail from %s dropped after 48 h: %s", account, last)
		return
	}
	nb, _ := json.Marshal(q)
	_ = m.h.Sys.WriteFile(envFile, nb, 0o600, 0, 0)
}

// wholeResult: a relay takes or refuses the message for all recipients.
func wholeResult(rcpts []string, err error) rcptResult {
	res := rcptResult{Bounced: map[string]string{}, Deferred: map[string]string{}}
	for _, r := range rcpts {
		switch {
		case err == nil:
			res.Sent = append(res.Sent, r)
		case permanent(err):
			res.Bounced[r] = smtpText(err)
		default:
			res.Deferred[r] = smtpText(err)
		}
	}
	return res
}

// stripBcc removes Bcc headers (the recipients are in the envelope).
func stripBcc(msg []byte) []byte {
	var out bytes.Buffer
	r := bufio.NewReader(bytes.NewReader(msg))
	skipping := false
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			trim := bytes.TrimRight(line, "\r\n")
			if len(trim) == 0 { // end of headers
				out.Write(line)
				rest, _ := io.ReadAll(r)
				out.Write(rest)
				break
			}
			if skipping && (line[0] == ' ' || line[0] == '\t') {
				continue
			}
			skipping = bytes.HasPrefix(bytes.ToLower(line), []byte("bcc:"))
			if !skipping {
				out.Write(line)
			}
		}
		if err != nil {
			break
		}
	}
	return out.Bytes()
}

// setupError: the relay could not be used at all (connection, TLS,
// sign-in). The message waits and is tried again: a refused sign-in is a
// broken link (EmailZit replaced or removed the relay login), not the
// recipient's answer. It has no Unwrap on purpose, so a 535 is not taken
// for a permanent refusal of the message.
type setupError struct {
	stage string
	err   error
}

func (e *setupError) Error() string { return "relay " + e.stage + ": " + e.err.Error() }

// sendVia hands a message to a relay with a login: the administrator's
// SMTP server (from empty: the envelope sender is <account>@<relay
// domain>, as before) or EmailZit's relay (from = the prepared sender on
// the From domain; the message is complete already).
func sendVia(ctx context.Context, relay RelayConfig, account, from string, q queued, msg []byte) error {
	addr := net.JoinHostPort(relay.Host, strconv.Itoa(relay.Port))
	d := net.Dialer{Timeout: 20 * time.Second}
	var conn net.Conn
	var err error
	if relay.Security == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: relay.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return &setupError{"connection", err}
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	c, err := smtp.NewClient(conn, relay.Host)
	if err != nil {
		_ = conn.Close()
		return &setupError{"greeting", err}
	}
	defer c.Close()
	if err := c.Hello(helloName(relay.Helo)); err != nil {
		return &setupError{"greeting", err}
	}
	if relay.Security == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: relay.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return &setupError{"STARTTLS", err}
		}
	}
	if relay.User != "" {
		if err := c.Auth(smtp.PlainAuth("", relay.User, relay.Password, relay.Host)); err != nil {
			return &setupError{"sign-in", err}
		}
	}
	head := ""
	if from == "" {
		from = account + "@" + relay.Domain
		if relay.Domain == "" {
			from = account + "@localhost"
		}
		head = "X-HostZit-Account: " + account + "\r\n"
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, t := range q.To {
		if _, err := mail.ParseAddress(t); err != nil {
			continue
		}
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(head)); err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
