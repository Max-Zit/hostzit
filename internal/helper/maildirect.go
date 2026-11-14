package helper

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Website mail sent by HostZit itself (no EmailZit, no relay): the mailer
// looks up the MX of every recipient domain and delivers on port 25 with
// STARTTLS when offered, signs with the DKIM key of the sender's domain and
// writes every outcome into the account's mail log, which the customer sees.
// The From address must be on a domain of the account (its websites,
// aliases and DNS zones), and the envelope sender is on the same domain, so
// SPF, DKIM and DMARC line up and nobody sends in another customer's name.

// mailAccountDir holds <account>.json: the account's mail domains and keys.
const mailAccountDir = "/etc/hostzit/mail"

// mailLogDir holds <account>.jsonl: the outcome of every message.
const mailLogDir = "/var/lib/hostzit/maillog"

// DKIMSelector is the selector of HostZit's DKIM keys.
const DKIMSelector = "hz1"

// MailAccount is what the mailer knows of an account's domains.
type MailAccount struct {
	// Primary is the domain of a From address the mailer adds when a
	// message has none.
	Primary string `json:"primary"`
	// Domains are the domains the account may send from (subdomains too).
	Domains []string  `json:"domains"`
	DKIM    []DKIMKey `json:"dkim"`
}

// DKIMKey is a private signing key of a domain (PKCS#8 PEM).
type DKIMKey struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	Key      string `json:"key"`
}

type mailAccountArgs struct {
	Account string      `json:"account"`
	Mail    MailAccount `json:"mail"`
}

func (h *Helper) mailAccount(_ context.Context, a mailAccountArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	m := a.Mail
	if len(m.Domains) > 500 || len(m.DKIM) > 500 {
		return nil, userErr("too many mail domains")
	}
	for _, d := range m.Domains {
		if !hosting.ValidDomain(d) {
			return nil, userErr("invalid mail domain")
		}
	}
	if m.Primary != "" && !hosting.ValidDomain(m.Primary) {
		return nil, userErr("invalid mail domain")
	}
	for _, k := range m.DKIM {
		if !hosting.ValidDomain(k.Domain) || !selectorRE(k.Selector) {
			return nil, userErr("invalid DKIM key")
		}
		if _, err := parseDKIMKey(k.Key); err != nil {
			return nil, userErr("invalid DKIM key")
		}
	}
	if err := h.Sys.Mkdir(mailAccountDir, 0o700, 0, 0); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(m)
	return nil, h.Sys.WriteFile(mailAccountDir+"/"+a.Account+".json", b, 0o600, 0, 0)
}

func selectorRE(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func parseDKIMKey(p string) (crypto.Signer, error) {
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		return nil, errors.New("no PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok || rk.N.BitLen() < 1024 {
		return nil, errors.New("not an RSA key")
	}
	return rk, nil
}

// NewDKIMKey makes an RSA key: the PKCS#8 PEM and the DNS record value.
func NewDKIMKey() (priv, record string, err error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub), nil
}

func (m *mailer) account(account string) MailAccount {
	var ma MailAccount
	if b, err := m.h.Sys.ReadFile(mailAccountDir + "/" + account + ".json"); err == nil {
		_ = json.Unmarshal(b, &ma)
	}
	return ma
}

// covers reports whether domain is d or below it.
func covers(d, domain string) bool {
	return domain == d || strings.HasSuffix(domain, "."+d)
}

// allows reports whether the account may send from domain.
func (ma MailAccount) allows(domain string) bool {
	for _, d := range ma.Domains {
		if covers(d, domain) {
			return true
		}
	}
	return false
}

// key is the DKIM key for a From domain (the closest domain with a key).
func (ma MailAccount) key(domain string) *DKIMKey {
	var best *DKIMKey
	for i := range ma.DKIM {
		k := &ma.DKIM[i]
		if covers(k.Domain, domain) && (best == nil || len(k.Domain) > len(best.Domain)) {
			best = k
		}
	}
	return best
}

func addrDomain(a string) string {
	i := strings.LastIndexByte(a, '@')
	if i < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(a[i+1:], "."))
}

// prepared is a message ready for direct delivery or EmailZit's relay.
type prepared struct {
	From    string // envelope sender
	Header  string // address in the From header
	Msg     []byte
	Refusal string // not sent: why
	Domain  string
	Signed  string // DKIM d= when signed
}

// prepare checks the sender and completes the message: From (when
// missing), Date, Message-ID, the account header and, with sign, DKIM.
func prepare(account string, ma MailAccount, q queued, msg []byte, sign bool, now time.Time) prepared {
	msg = crlf(msg)
	pm, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return prepared{Refusal: "the message has no valid headers"}
	}
	var add []string
	from := ""
	if l, err := pm.Header.AddressList("From"); err == nil && len(l) > 0 {
		from = l[0].Address
	} else if strings.TrimSpace(pm.Header.Get("From")) != "" {
		return prepared{Refusal: "the From header is not a valid address"}
	}
	if from == "" {
		if ma.Primary == "" {
			return prepared{Refusal: "the message has no From address and the account has no domain"}
		}
		from = account + "@" + ma.Primary
		add = append(add, "From: "+from)
	}
	dom := addrDomain(from)
	if !hosting.ValidDomain(dom) || !ma.allows(dom) {
		return prepared{Header: from, Refusal: "the From address " + from + " is not on a domain of this hosting account"}
	}
	env := from
	if q.From != "" && addrDomain(q.From) == dom {
		if _, err := mail.ParseAddress(q.From); err == nil {
			env = q.From
		}
	}
	if pm.Header.Get("Date") == "" {
		add = append(add, "Date: "+now.Format(time.RFC1123Z))
	}
	if pm.Header.Get("Message-Id") == "" {
		var rb [12]byte
		_, _ = rand.Read(rb[:])
		add = append(add, "Message-ID: <"+hex.EncodeToString(rb[:])+"@"+dom+">")
	}
	add = append(add, "X-HostZit-Account: "+account)
	var b bytes.Buffer
	for _, h := range add {
		b.WriteString(h + "\r\n")
	}
	b.Write(stripBcc(msg))
	out := b.Bytes()
	p := prepared{From: env, Header: from, Domain: dom, Msg: out}
	if sign {
		if k := ma.key(dom); k != nil {
			if key, err := parseDKIMKey(k.Key); err == nil {
				if sig, err := dkimSign(out, k.Domain, k.Selector, key, now); err == nil {
					p.Msg = append([]byte(sig), out...)
					p.Signed = k.Domain
				}
			}
		}
	}
	return p
}

// crlf turns lone LF into CRLF (SMTP and DKIM want CRLF).
func crlf(b []byte) []byte {
	if !bytes.Contains(b, []byte("\n")) {
		return b
	}
	out := make([]byte, 0, len(b)+len(b)/40)
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}

// splitMessage splits a CRLF message into headers (with the last CRLF) and body.
func splitMessage(msg []byte) (head, body []byte) {
	if bytes.HasPrefix(msg, []byte("\r\n")) {
		return nil, msg[2:]
	}
	i := bytes.Index(msg, []byte("\r\n\r\n"))
	if i < 0 {
		return msg, nil
	}
	return msg[:i+2], msg[i+4:]
}

// dkimHeaders are signed when present (the last instance of each).
var dkimHeaders = []string{"from", "to", "cc", "subject", "date", "message-id", "reply-to", "in-reply-to", "references", "mime-version", "content-type", "content-transfer-encoding"}

// dkimSign returns the DKIM-Signature header (RFC 6376, rsa-sha256,
// relaxed/relaxed) for a CRLF message.
func dkimSign(msg []byte, d, sel string, key crypto.Signer, now time.Time) (string, error) {
	head, body := splitMessage(msg)
	bh := sha256.Sum256(relaxedBody(body))
	fields := headerFields(head)
	var names []string
	var signed bytes.Buffer
	for _, n := range dkimHeaders {
		for i := len(fields) - 1; i >= 0; i-- {
			if fields[i].name == n {
				signed.WriteString(relaxedHeader(fields[i].raw) + "\r\n")
				names = append(names, n)
				break
			}
		}
	}
	if len(names) == 0 || names[0] != "from" {
		return "", errors.New("no From header")
	}
	val := "v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + d + "; s=" + sel + "; t=" + strconv.FormatInt(now.Unix(), 10) +
		"; h=" + strings.Join(names, ":") + "; bh=" + base64.StdEncoding.EncodeToString(bh[:]) + "; b="
	signed.WriteString(relaxedHeader("DKIM-Signature: " + val))
	sum := sha256.Sum256(signed.Bytes())
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return "DKIM-Signature: " + val + base64.StdEncoding.EncodeToString(sig) + "\r\n", nil
}

type headerField struct {
	name string // lower case
	raw  string // the whole field, folded as in the message, without the last CRLF
}

func headerFields(head []byte) []headerField {
	var out []headerField
	for _, line := range strings.SplitAfter(string(head), "\r\n") {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(out) > 0 {
			out[len(out)-1].raw += "\r\n" + strings.TrimSuffix(line, "\r\n")
			continue
		}
		line = strings.TrimSuffix(line, "\r\n")
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out = append(out, headerField{name: strings.ToLower(strings.TrimSpace(name)), raw: line})
	}
	return out
}

// relaxedHeader canonicalizes one header field (RFC 6376 3.4.2).
func relaxedHeader(raw string) string {
	name, val, _ := strings.Cut(raw, ":")
	val = strings.ReplaceAll(val, "\r\n", "")
	return strings.ToLower(strings.TrimSpace(name)) + ":" + strings.TrimSpace(squeezeWSP(val))
}

func squeezeWSP(s string) string {
	var b strings.Builder
	sp := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			sp = true
			continue
		}
		if sp {
			b.WriteByte(' ')
			sp = false
		}
		b.WriteByte(c)
	}
	if sp {
		b.WriteByte(' ')
	}
	return b.String()
}

// relaxedBody canonicalizes the body (RFC 6376 3.4.4).
func relaxedBody(body []byte) []byte {
	lines := strings.Split(string(body), "\r\n")
	// a body ending in CRLF gives an empty last element
	for len(lines) > 0 && strings.TrimRight(lines[len(lines)-1], " \t") == "" {
		lines = lines[:len(lines)-1]
	}
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(strings.TrimRight(squeezeWSP(l), " "))
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// rcptResult is the outcome of the recipients of one delivery.
type rcptResult struct {
	Sent     []string
	Bounced  map[string]string // permanent: the receiving server's answer
	Deferred map[string]string // try again later
	Host     string            // the MX that took the message
}

// permanent reports an SMTP 5xx answer.
func permanent(err error) bool {
	var te *textproto.Error
	return errors.As(err, &te) && te.Code >= 500
}

func smtpText(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return strings.ToValidUTF8(s, "")
}

// mxHosts are the hosts that take mail for a domain, in order.
func mxHosts(ctx context.Context, r *net.Resolver, domain string) (hosts []string, perm error, temp error) {
	mx, err := r.LookupMX(ctx, domain)
	var de *net.DNSError
	if err != nil && !(errors.As(err, &de) && de.IsNotFound) {
		return nil, nil, fmt.Errorf("DNS of %s: %w", domain, err)
	}
	if len(mx) == 1 && (mx[0].Host == "." || mx[0].Host == "") {
		return nil, fmt.Errorf("%s accepts no mail (null MX)", domain), nil
	}
	sort.SliceStable(mx, func(i, j int) bool { return mx[i].Pref < mx[j].Pref })
	for _, m := range mx {
		hosts = append(hosts, strings.TrimSuffix(m.Host, "."))
	}
	if len(hosts) > 0 {
		return hosts, nil, nil
	}
	// no MX: the domain itself (RFC 5321 5.1)
	if _, err := r.LookupIPAddr(ctx, domain); err != nil {
		if errors.As(err, &de) && de.IsNotFound {
			return nil, fmt.Errorf("the domain %s does not exist", domain), nil
		}
		return nil, nil, fmt.Errorf("DNS of %s: %w", domain, err)
	}
	return []string{domain}, nil, nil
}

// directDialer reaches port 25 of the receiving servers (a test sets its own).
var directDialer = func(ctx context.Context, host string) (net.Conn, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	// IPv4 first: receivers judge IPv6 senders harder (reverse DNS)
	sort.SliceStable(ips, func(i, j int) bool { return ips[i].IP.To4() != nil && ips[j].IP.To4() == nil })
	if len(ips) > 3 {
		ips = ips[:3]
	}
	var last error = errors.New("no address")
	for _, ip := range ips {
		d := net.Dialer{Timeout: 30 * time.Second}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.IP.String(), "25"))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// directMX looks up the receiving hosts of a domain (a test sets its own).
var directMX = func(ctx context.Context, domain string) ([]string, error, error) {
	return mxHosts(ctx, net.DefaultResolver, domain)
}

// deliverDirect sends a message to the MX hosts of its recipients.
func deliverDirect(ctx context.Context, helo, from string, rcpts []string, msg []byte) rcptResult {
	res := rcptResult{Bounced: map[string]string{}, Deferred: map[string]string{}}
	byDomain := map[string][]string{}
	var order []string
	for _, r := range rcpts {
		d := addrDomain(r)
		if d == "" {
			res.Bounced[r] = "not an address"
			continue
		}
		if _, ok := byDomain[d]; !ok {
			order = append(order, d)
		}
		byDomain[d] = append(byDomain[d], r)
	}
	for _, d := range order {
		list := byDomain[d]
		hosts, perm, temp := directMX(ctx, d)
		if perm != nil || temp != nil {
			for _, r := range list {
				if perm != nil {
					res.Bounced[r] = perm.Error()
				} else {
					res.Deferred[r] = temp.Error()
				}
			}
			continue
		}
		left := list
		var lastErr string
		for _, h := range hosts {
			if len(hosts) > 5 && h == hosts[5] {
				break
			}
			sent, bounced, deferred, err := smtpSession(ctx, h, helo, from, left, msg)
			if err != nil { // could not talk to this host: the next one
				lastErr = h + ": " + smtpText(err)
				continue
			}
			res.Sent = append(res.Sent, sent...)
			if len(sent) > 0 {
				res.Host = h
			}
			for r, why := range bounced {
				res.Bounced[r] = h + ": " + why
			}
			left = nil
			for r, why := range deferred {
				res.Deferred[r] = h + ": " + why
			}
			break
		}
		for _, r := range left {
			res.Deferred[r] = lastErr
		}
	}
	return res
}

// smtpSession delivers to one MX host. err means the host could not be
// used at all (try the next one).
func smtpSession(ctx context.Context, host, helo, from string, rcpts []string, msg []byte) (sent []string, bounced, deferred map[string]string, err error) {
	bounced, deferred = map[string]string{}, map[string]string{}
	try := func(useTLS bool) (tlsFailed bool, err error) {
		conn, err := directDialer(ctx, host)
		if err != nil {
			return false, err
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return false, err
		}
		defer c.Close()
		if err := c.Hello(helo); err != nil {
			return false, err
		}
		if ok, _ := c.Extension("STARTTLS"); ok && useTLS {
			// opportunistic: encrypted even when the certificate is not
			// one we can check (RFC 7435); a refused handshake is retried
			// in the clear, as every mail server does
			// #nosec G402 -- opportunistic STARTTLS between mail servers
			if err := c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}); err != nil {
				return true, err
			}
		}
		if err := c.Mail(from); err != nil {
			if permanent(err) {
				for _, r := range rcpts {
					bounced[r] = smtpText(err)
				}
				return false, nil
			}
			return false, err
		}
		var ok []string
		for _, r := range rcpts {
			if err := c.Rcpt(r); err != nil {
				if permanent(err) {
					bounced[r] = smtpText(err)
				} else {
					deferred[r] = smtpText(err)
				}
				continue
			}
			ok = append(ok, r)
		}
		if len(ok) == 0 {
			_ = c.Quit()
			return false, nil
		}
		w, err := c.Data()
		if err == nil {
			if _, err = w.Write(msg); err == nil {
				err = w.Close()
			}
		}
		if err != nil {
			for _, r := range ok {
				if permanent(err) {
					bounced[r] = smtpText(err)
				} else {
					deferred[r] = smtpText(err)
				}
			}
			return false, nil
		}
		sent = ok
		_ = c.Quit()
		return false, nil
	}
	tlsFailed, err := try(true)
	if tlsFailed {
		bounced, deferred = map[string]string{}, map[string]string{}
		_, err = try(false)
	}
	return sent, bounced, deferred, err
}

// ---- the mail log

// MailLogEntry is the outcome of a message, as the customer sees it.
type MailLogEntry struct {
	At      time.Time `json:"at"`
	ID      string    `json:"id"`
	From    string    `json:"from,omitempty"`
	To      []string  `json:"to"`
	Subject string    `json:"subject,omitempty"`
	// Status: sent, bounced (the receiving server refused it), refused
	// (HostZit did not send it), failed (dropped after 48 hours)
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Via    string `json:"via,omitempty"` // direct, emailzit, relay
}

const (
	mailLogKeep = 30 * 24 * time.Hour
	mailLogMax  = 2000
)

func (h *Helper) recordMail(account string, e MailLogEntry) {
	if hosting.ValidAccount(account) != nil {
		return
	}
	if len(e.Subject) > 200 {
		e.Subject = strings.ToValidUTF8(e.Subject[:200], "")
	}
	path := mailLogDir + "/" + account + ".jsonl"
	old, _ := h.Sys.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(old)), "\n")
	var keep []string
	cut := time.Now().Add(-mailLogKeep)
	for _, l := range lines {
		var x MailLogEntry
		if l != "" && json.Unmarshal([]byte(l), &x) == nil && x.At.After(cut) {
			keep = append(keep, l)
		}
	}
	if len(keep) >= mailLogMax {
		keep = keep[len(keep)-mailLogMax+1:]
	}
	b, _ := json.Marshal(e)
	keep = append(keep, string(b))
	_ = h.Sys.Mkdir(mailLogDir, 0o700, 0, 0)
	_ = h.Sys.WriteFile(path, []byte(strings.Join(keep, "\n")+"\n"), 0o600, 0, 0)
	if e.Status != "sent" {
		h.countFailure(account, e)
	}
}

type mailLogArgs struct {
	Account string `json:"account"`
	Since   string `json:"since,omitempty"` // RFC 3339: only newer entries
}

// mailLog gives the account's log, newest first (at most 300).
func (h *Helper) mailLog(_ context.Context, a mailLogArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	var since time.Time
	if a.Since != "" {
		t, err := time.Parse(time.RFC3339, a.Since)
		if err != nil {
			return nil, userErr("invalid time")
		}
		since = t
	}
	b, _ := h.Sys.ReadFile(mailLogDir + "/" + a.Account + ".jsonl")
	out := []MailLogEntry{}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0 && len(out) < 300; i-- {
		var x MailLogEntry
		if lines[i] != "" && json.Unmarshal([]byte(lines[i]), &x) == nil && x.At.After(since) {
			out = append(out, x)
		}
	}
	return out, nil
}

// ---- the check of direct sending

// MailCheck says whether this server can deliver mail itself.
type MailCheck struct {
	At       time.Time  `json:"at"`
	Port25   bool       `json:"port25"`
	Port25To string     `json:"port25_to,omitempty"`
	Error    string     `json:"error,omitempty"`
	PTR      []PTRCheck `json:"ptr"`
}

// PTRCheck is the reverse name of one address of the server.
type PTRCheck struct {
	IP    string   `json:"ip"`
	Names []string `json:"names"`
	OK    bool     `json:"ok"` // a name that is the server name and points back
}

type mailCheckArgs struct {
	Helo string   `json:"helo"`
	IPs  []string `json:"ips"`
}

// mailCheck tries port 25 of a large mail provider and the reverse names of
// the server's addresses.
func (h *Helper) mailCheck(ctx context.Context, a mailCheckArgs) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	out := MailCheck{At: time.Now().UTC(), PTR: []PTRCheck{}}
	hosts, _, err := directMX(ctx, "gmail.com")
	if err == nil && len(hosts) > 0 {
		out.Port25To = hosts[0]
		c, err := directDialer(ctx, hosts[0])
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			line, _ := textproto.NewReader(bufio.NewReader(c)).ReadLine()
			_ = c.Close()
			out.Port25 = strings.HasPrefix(line, "220")
			if !out.Port25 {
				out.Error = "no greeting from " + hosts[0]
			}
		} else {
			out.Error = smtpText(err)
		}
	} else if err != nil {
		out.Error = smtpText(err)
	}
	helo := strings.ToLower(strings.TrimSuffix(a.Helo, "."))
	for _, ip := range a.IPs {
		if net.ParseIP(ip) == nil {
			continue
		}
		p := PTRCheck{IP: ip}
		names, _ := net.DefaultResolver.LookupAddr(ctx, ip)
		for _, n := range names {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
			p.Names = append(p.Names, n)
			if n == helo && helo != "" {
				if addrs, err := net.DefaultResolver.LookupHost(ctx, n); err == nil {
					for _, x := range addrs {
						if net.ParseIP(x).Equal(net.ParseIP(ip)) {
							p.OK = true
						}
					}
				}
			}
		}
		out.PTR = append(out.PTR, p)
	}
	return out, nil
}

func helloName(helo string) string {
	if helo != "" {
		return helo
	}
	n, _ := os.Hostname()
	return n
}

// MailFailures counts an account's undelivered messages since the panel
// last asked (for its notices).
type MailFailures struct {
	N    int    `json:"n"`
	Last string `json:"last"`
}

const mailFailuresFile = mailLogDir + "/failures.json"

func (h *Helper) countFailure(account string, e MailLogEntry) {
	f := map[string]MailFailures{}
	if b, err := h.Sys.ReadFile(mailFailuresFile); err == nil {
		_ = json.Unmarshal(b, &f)
	}
	x := f[account]
	x.N++
	x.Last = strings.Join(e.To, ", ") + ": " + e.Status + " (" + e.Detail + ")"
	if len(x.Last) > 400 {
		x.Last = strings.ToValidUTF8(x.Last[:400], "")
	}
	f[account] = x
	b, _ := json.Marshal(f)
	_ = h.Sys.WriteFile(mailFailuresFile, b, 0o600, 0, 0)
}

// mailFailures gives the counts and starts them again.
func (h *Helper) mailFailures(_ context.Context, _ struct{}) (any, error) {
	f := map[string]MailFailures{}
	if b, err := h.Sys.ReadFile(mailFailuresFile); err == nil {
		_ = json.Unmarshal(b, &f)
		_ = h.Sys.Remove(mailFailuresFile)
	}
	return f, nil
}
