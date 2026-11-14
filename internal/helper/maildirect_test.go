package helper

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The examples of RFC 6376 3.4.5.
func TestRelaxedCanonicalization(t *testing.T) {
	if got := relaxedHeader("A: X") + "\r\n" + relaxedHeader("B : Y\t\r\n\tZ  "); got != "a:X\r\nb:Y Z" {
		t.Fatalf("%q", got)
	}
	if got := string(relaxedBody([]byte(" C \r\nD \t E\r\n\r\n\r\n"))); got != " C\r\nD E\r\n" {
		t.Fatalf("%q", got)
	}
	if got := string(relaxedBody(nil)); got != "" {
		t.Fatalf("empty body %q", got)
	}
	if got := string(crlf([]byte("a\nb\r\nc\n"))); got != "a\r\nb\r\nc\r\n" {
		t.Fatalf("%q", got)
	}
}

// verifyDKIM checks a signature the way a receiver does.
func verifyDKIM(t *testing.T, msg []byte, record string) {
	t.Helper()
	head, body := splitMessage(msg)
	fields := headerFields(head)
	if len(fields) == 0 || fields[0].name != "dkim-signature" {
		t.Fatal("no DKIM-Signature first")
	}
	sigRaw := fields[0].raw
	tags := map[string]string{}
	_, val, _ := strings.Cut(sigRaw, ":")
	for _, p := range strings.Split(val, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		tags[k] = strings.TrimSpace(v)
	}
	bh := sha256.Sum256(relaxedBody(body))
	if tags["bh"] != base64.StdEncoding.EncodeToString(bh[:]) {
		t.Fatal("body hash")
	}
	var in strings.Builder
	used := map[int]bool{}
	for _, n := range strings.Split(tags["h"], ":") {
		for i := len(fields) - 1; i > 0; i-- {
			if fields[i].name == n && !used[i] {
				used[i] = true
				in.WriteString(relaxedHeader(fields[i].raw) + "\r\n")
				break
			}
		}
	}
	in.WriteString(relaxedHeader(strings.Replace(sigRaw, "b="+tags["b"], "b=", 1)))
	_, p, _ := strings.Cut(record, "p=")
	der, _ := base64.StdEncoding.DecodeString(p)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(tags["b"])
	sum := sha256.Sum256([]byte(in.String()))
	if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, sum[:], sig); err != nil {
		t.Fatal("signature does not verify:", err)
	}
	if tags["d"] == "" || tags["s"] != DKIMSelector || tags["c"] != "relaxed/relaxed" || !strings.HasPrefix(tags["h"], "from") {
		t.Fatal(tags)
	}
}

// fakeMX is a receiving mail server.
type fakeMX struct {
	ln   net.Listener
	mu   sync.Mutex
	got  []string // MAIL FROM, RCPTs and the data of each message
	auth string
}

func newFakeMX(t *testing.T) *fakeMX {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeMX{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeMX) add(s string) {
	f.mu.Lock()
	f.got = append(f.got, s)
	f.mu.Unlock()
}

func (f *fakeMX) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.got, "\n")
}

func (f *fakeMX) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	say("220 mx.test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			f.add(line)
			say("250-mx.test")
			say("250 AUTH PLAIN")
		case strings.HasPrefix(up, "AUTH PLAIN"):
			f.mu.Lock()
			f.auth = strings.TrimSpace(line[len("AUTH PLAIN"):])
			f.mu.Unlock()
			say("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.add(line)
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			switch {
			case strings.Contains(line, "bad@"):
				say("550 5.1.1 no such user")
			case strings.Contains(line, "later@"):
				say("451 4.3.0 try again")
			default:
				f.add(line)
				say("250 ok")
			}
		case up == "DATA":
			say("354 go on")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.add("DATA\n" + b.String())
			say("250 2.0.0 queued as 123")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func useFakeMX(t *testing.T, f *fakeMX) {
	oldMX, oldDial := directMX, directDialer
	directMX = func(_ context.Context, domain string) ([]string, error, error) {
		if domain == "nowhere.test" {
			return nil, nil, errors.New("DNS of nowhere.test: timeout")
		}
		return []string{"mx." + domain}, nil, nil
	}
	directDialer = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", f.ln.Addr().String())
	}
	t.Cleanup(func() { directMX, directDialer = oldMX, oldDial })
}

func queueMail(t *testing.T, root, account, id string, q queued, msg string) {
	t.Helper()
	dir := filepath.Join(root, "var/spool/hostzit", account)
	_ = os.MkdirAll(dir, 0o700)
	b, _ := json.Marshal(q)
	_ = os.WriteFile(filepath.Join(dir, id+".eml"), []byte(msg), 0o600)
	_ = os.WriteFile(filepath.Join(dir, id+".json"), b, 0o600)
}

func mailLogOf(t *testing.T, h *Helper, account string) []MailLogEntry {
	t.Helper()
	r := call(t, h, "mail.log", mailLogArgs{Account: account})
	if !r.OK {
		t.Fatal(r.Error)
	}
	var out []MailLogEntry
	_ = json.Unmarshal(r.Result, &out)
	return out
}

func TestWebsiteMailDirect(t *testing.T) {
	h, _, root, _ := newTest(t)
	f := newFakeMX(t)
	useFakeMX(t, f)
	priv, record, err := NewDKIMKey()
	if err != nil {
		t.Fatal(err)
	}
	if r := call(t, h, "mail.account", mailAccountArgs{Account: "shop1", Mail: MailAccount{Primary: "shop.test", Domains: []string{"shop.test", "shop-alias.test"},
		DKIM: []DKIMKey{{Domain: "shop.test", Selector: DKIMSelector, Key: priv}}}}); !r.OK {
		t.Fatal(r.Error)
	}
	// limits of the account: 10 messages an hour
	_ = os.MkdirAll(filepath.Join(root, "etc/hostzit/accounts"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "etc/hostzit/accounts/shop1.json"), []byte(`{"name":"shop1","number":1,"limits":{"mail_per_hour":10}}`), 0o600)
	now := time.Now().UTC()
	queueMail(t, root, "shop1", "a1", queued{To: []string{"ok@dest.test", "bad@dest.test", "later@dest.test"}, At: now, Subject: "Order"},
		"From: WordPress <wordpress@www.shop.test>\nTo: ok@dest.test\nSubject: Order\n\nHello  \nthere\n")
	queueMail(t, root, "shop1", "a2", queued{To: []string{"ok@dest.test"}, At: now, Subject: "Spoof"},
		"From: boss@bank.test\nSubject: Spoof\n\nx\n")
	queueMail(t, root, "shop1", "a3", queued{To: []string{"ok@nowhere.test"}, At: now.Add(-49 * time.Hour), Subject: "Old"},
		"From: info@shop.test\nSubject: Old\n\nx\n")
	queueMail(t, root, "shop1", "a4", queued{To: []string{"ok@dest.test"}, At: now, Subject: "No From"},
		"Subject: No From\n\nx\n")
	m := &mailer{h: h, sent: map[string][]time.Time{}}
	m.round(t.Context()) // no relay file: HostZit sends itself

	got := f.all()
	if !strings.Contains(got, "MAIL FROM:<wordpress@www.shop.test>") || !strings.Contains(got, "RCPT TO:<ok@dest.test>") || strings.Contains(got, "bank.test") {
		t.Fatal(got)
	}
	// the signed message verifies, and the From-less one got the account's address
	var msgs []string
	for _, part := range strings.Split(got, "DATA\n")[1:] {
		if end := strings.Index(part, "\nEHLO"); end > 0 {
			part = part[:end]
		}
		msgs = append(msgs, part)
	}
	if len(msgs) != 2 {
		t.Fatalf("%d messages delivered:\n%s", len(msgs), got)
	}
	verifyDKIM(t, []byte(msgs[0]), record)
	if !strings.Contains(msgs[0], "Message-ID: <") || !strings.Contains(msgs[0], "Date: ") || !strings.Contains(msgs[0], "X-HostZit-Account: shop1") {
		t.Fatal(msgs[0])
	}
	if !strings.Contains(msgs[1], "From: shop1@shop.test") {
		t.Fatal(msgs[1])
	}
	log := mailLogOf(t, h, "shop1")
	status := map[string]string{}
	for _, e := range log {
		status[e.Subject+" "+strings.Join(e.To, ",")] = e.Status
	}
	want := map[string]string{"Order ok@dest.test": "sent", "Order bad@dest.test": "bounced", "Spoof ok@dest.test": "refused", "Old ok@nowhere.test": "failed", "No From ok@dest.test": "sent"}
	for k, v := range want {
		if status[k] != v {
			t.Fatalf("%s: %q (log %+v)", k, status[k], log)
		}
	}
	// only the deferred recipient is left in the queue
	r := call(t, h, "mail.queue", mailQueueArgs{Account: "shop1"})
	var q []QueueItem
	_ = json.Unmarshal(r.Result, &q)
	if len(q) != 1 || len(q[0].To) != 1 || q[0].To[0] != "later@dest.test" || !strings.Contains(q[0].LastErr, "451") {
		t.Fatalf("queue %+v", q)
	}
}

func TestWebsiteMailThroughEmailZit(t *testing.T) {
	h, _, root, _ := newTest(t)
	f := newFakeMX(t)
	_, port, _ := net.SplitHostPort(f.ln.Addr().String())
	var p int
	_ = json.Unmarshal([]byte(port), &p)
	if r := call(t, h, "mail.relay", relayArgs{Relay: RelayConfig{Mode: "emailzit", Host: "127.0.0.1", Port: p, Security: "none", User: "hostzit-relay@mail.test", Password: "pw", Helo: "host1.hostzit.test"}}); !r.OK {
		t.Fatal(r.Error)
	}
	if r := call(t, h, "mail.account", mailAccountArgs{Account: "shop1", Mail: MailAccount{Primary: "shop.test", Domains: []string{"shop.test"}}}); !r.OK {
		t.Fatal(r.Error)
	}
	_ = os.MkdirAll(filepath.Join(root, "etc/hostzit/accounts"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "etc/hostzit/accounts/shop1.json"), []byte(`{"name":"shop1","number":1,"limits":{"mail_per_hour":10}}`), 0o600)
	queueMail(t, root, "shop1", "b1", queued{From: "bounce@other.test", To: []string{"ok@dest.test"}, At: time.Now(), Subject: "Hi"},
		"From: info@shop.test\nSubject: Hi\n\nx\n")
	m := &mailer{h: h, sent: map[string][]time.Time{}}
	m.round(t.Context())
	got := f.all()
	// the envelope sender is on the From domain (EmailZit refuses others),
	// EmailZit signs, so HostZit does not
	if !strings.Contains(got, "EHLO host1.hostzit.test") || !strings.Contains(got, "MAIL FROM:<info@shop.test>") || strings.Contains(got, "DKIM-Signature") {
		t.Fatal(got)
	}
	f.mu.Lock()
	auth := f.auth
	f.mu.Unlock()
	if b, _ := base64.StdEncoding.DecodeString(auth); string(b) != "\x00hostzit-relay@mail.test\x00pw" {
		t.Fatalf("auth %q", b)
	}
	if log := mailLogOf(t, h, "shop1"); len(log) != 1 || log[0].Status != "sent" || log[0].Via != "emailzit" {
		t.Fatalf("%+v", log)
	}
}
