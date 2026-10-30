package netacl

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func mustParse(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	p, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParse(t *testing.T) {
	p := mustParse(t, "192.168.1.77/24", "10.1.2.3", "2001:db8::/32", "::ffff:10.9.9.9")
	if got := Strings(p); !reflect.DeepEqual(got, []string{"192.168.1.0/24", "10.1.2.3", "2001:db8::/32", "10.9.9.9"}) {
		t.Fatalf("got %v", got)
	}
	for _, bad := range []string{"300.1.1.1", "10.0.0.0/33", "example.com", "::ffff:10.0.0.0/104", ""} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	many := make([]string, MaxEntries+1)
	for i := range many {
		many[i] = "10.0.0.1"
	}
	if _, err := Parse(many); err == nil {
		t.Error("too many entries accepted")
	}
}

func TestSplit(t *testing.T) {
	got := Split("10.0.0.0/8, 192.168.1.5\r\n# office\n  2001:db8::1 ; 172.16.0.0/12 # vpn\n")
	want := []string{"10.0.0.0/8", "192.168.1.5", "2001:db8::1", "172.16.0.0/12"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestManagementList(t *testing.T) {
	l := NewManagement(mustParse(t, "192.168.101.0/24"))
	cases := map[string]bool{
		"192.168.101.104:5000":     true,
		"192.168.102.1:5000":       false,
		"127.0.0.1:1":              true, // loopback is always allowed
		"[::1]:1":                  true,
		"[::ffff:192.168.101.9]:1": true,
		"8.8.8.8:443":              false,
		"garbage":                  false,
	}
	for a, want := range cases {
		if got := l.AllowsAddr(a); got != want {
			t.Errorf("%s: got %v want %v", a, got, want)
		}
	}
	l.Set(nil)
	if l.AllowsAddr("192.168.101.104:1") || !l.AllowsAddr("127.0.0.1:1") {
		t.Error("an empty management list must allow loopback only")
	}
}

func TestOptionalList(t *testing.T) {
	l := NewOptional(nil)
	if !l.AllowsAddr("8.8.8.8:1") {
		t.Error("empty optional list must allow everyone")
	}
	l.SetOptional(mustParse(t, "10.0.0.0/8"))
	if l.AllowsAddr("8.8.8.8:1") || !l.AllowsAddr("10.2.3.4:1") {
		t.Error("optional list with networks must filter")
	}
	if l.AllowsAddr("127.0.0.1:1") {
		t.Error("optional list must not allow loopback implicitly")
	}
}

func TestListenerRefusesBeforeHandshake(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := make(chan string, 1)
	l := &Listener{Listener: raw, List: NewOptional(mustParse(t, "10.0.0.0/8")), OnRefuse: func(r string) { refused <- r }}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
			t.Error("connection from 127.0.0.1 should have been refused")
		}
	}()
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-refused:
	case <-time.After(5 * time.Second):
		t.Fatal("no refusal")
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("refused connection still open")
	}
}
