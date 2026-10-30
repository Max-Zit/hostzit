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
// package and hands the messages to the relay the administrator set.

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
	b, _ := json.Marshal(r)
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

func (m *mailer) round(ctx context.Context) {
	b, err := m.h.Sys.ReadFile(relayFile)
	if err != nil {
		return
	}
	var relay RelayConfig
	if json.Unmarshal(b, &relay) != nil || relay.Host == "" {
		return
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
	err = sendVia(ctx, relay, account, q, msg)
	if err == nil {
		m.mu.Lock()
		m.sent[account] = append(m.sent[account], time.Now())
		m.mu.Unlock()
		_ = m.h.Sys.Remove(envFile)
		_ = m.h.Sys.Remove(emlFile)
		m.h.logf("mail from %s to %d recipients sent", account, len(q.To))
		return
	}
	q.Tries++
	q.LastErr = err.Error()
	q.NextTry = time.Now().Add(time.Duration(q.Tries*q.Tries) * time.Minute)
	if time.Since(q.At) > 48*time.Hour {
		_ = m.h.Sys.Remove(envFile)
		_ = m.h.Sys.Remove(emlFile)
		m.h.logf("mail from %s dropped after 48 h: %v", account, err)
		return
	}
	nb, _ := json.Marshal(q)
	_ = m.h.Sys.WriteFile(envFile, nb, 0o600, 0, 0)
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

func sendVia(ctx context.Context, relay RelayConfig, account string, q queued, msg []byte) error {
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
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	c, err := smtp.NewClient(conn, relay.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if relay.Security == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: relay.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if relay.User != "" {
		if err := c.Auth(smtp.PlainAuth("", relay.User, relay.Password, relay.Host)); err != nil {
			return err
		}
	}
	from := account + "@" + relay.Domain
	if relay.Domain == "" {
		from = account + "@localhost"
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
	if _, err := w.Write([]byte("X-HostZit-Account: " + account + "\r\n")); err != nil {
		return err
	}
	if _, err := w.Write(stripBcc(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// FirewallConf is the nftables table of HostZit: hosting accounts cannot
// send mail directly (spam from hacked websites), and blocked addresses
// cannot reach the server.
func FirewallConf(blocked []string) string {
	var v4, v6 []string
	for _, b := range blocked {
		if strings.Contains(b, ":") {
			v6 = append(v6, b)
		} else {
			v4 = append(v4, b)
		}
	}
	elems := func(l []string) string {
		if len(l) == 0 {
			return ""
		}
		return "\n        elements = { " + strings.Join(l, ", ") + " }"
	}
	return fmt.Sprintf(`# HostZit (generated, do not edit)
table inet hostzit {}
delete table inet hostzit
table inet hostzit {
    set blocked4 {
        type ipv4_addr
        flags interval%s
    }
    set blocked6 {
        type ipv6_addr
        flags interval%s
    }
    chain input {
        type filter hook input priority -5; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }
    chain output {
        type filter hook output priority 0; policy accept;
        meta skuid %d-%d tcp dport { 25, 465, 587 } counter reject with tcp reset
    }
}
`, elems(v4), elems(v6), hosting.UIDBase+1, hosting.UIDBase+hosting.MaxAccounts)
}

type firewallArgs struct {
	Blocked []string `json:"blocked"`
}

func (h *Helper) firewall(ctx context.Context, a firewallArgs) (any, error) {
	list, err := hosting.CleanNets(a.Blocked)
	if err != nil {
		return nil, userErr(err.Error())
	}
	if err := h.Sys.WriteFile("/etc/hostzit/firewall.nft", []byte(FirewallConf(list)), 0o600, 0, 0); err != nil {
		return nil, err
	}
	if _, err := h.Sys.Run(ctx, nil, "nft", "-f", "/etc/hostzit/firewall.nft"); err != nil {
		return nil, err
	}
	return map[string]int{"blocked": len(list)}, nil
}
