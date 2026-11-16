package helper

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveTCP runs h.Serve on a local port; stop ends it like SIGTERM does.
func serveTCP(t *testing.T, h *Helper) (c *Client, stop context.CancelFunc, served chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.PeerCheck = func(net.Conn) error { return nil }
	ctx, stop := context.WithCancel(context.Background())
	served = make(chan error, 1)
	go func() { served <- h.Serve(ctx, ln) }()
	c = &Client{Dial: func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}}
	t.Cleanup(stop)
	return c, stop, served
}

// blockNginxTest makes "nginx -t" wait until release is closed or its
// context ends (like exec.CommandContext); started is closed when it runs.
func blockNginxTest(h *Helper) (started, release chan struct{}) {
	o := h.Sys.(*OS)
	orig := o.Runner
	started, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	o.Runner = func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if name == "nginx" && len(args) > 0 && args[0] == "-t" {
			once.Do(func() { close(started) })
			select {
			case <-release:
			case <-ctx.Done():
				return nil, errors.New("signal: killed")
			}
		}
		return orig(ctx, stdin, name, args...)
	}
	return started, release
}

// A stop of the helper (an update restarts it) lets the change in flight
// finish: its test is not cut, so it is not rolled back, and the reload
// after it runs. Nothing new starts meanwhile.
func TestStopLetsTheChangeInFlightFinish(t *testing.T) {
	h, fr, _, _ := newTest(t)
	h.StopGrace = 5 * time.Second
	started, release := blockNginxTest(h)
	c, stop, served := serveTCP(t, h)
	res := make(chan error, 1)
	go func() {
		res <- c.Call(context.Background(), "service", serviceArgs{Name: "nginx", Action: "reload"}, nil)
	}()
	<-started
	stop()
	select {
	case err := <-served:
		t.Fatalf("Serve returned (%v) while a change was running", err)
	case <-time.After(300 * time.Millisecond):
	}
	if !h.stopping.Load() {
		t.Fatal("the helper does not know it stops")
	}
	if r := h.Do(context.Background(), Request{Op: "service", Args: []byte(`{"name":"nginx","action":"reload"}`)}); r.OK || r.Error != errStopping.Error() {
		t.Fatalf("a new change started while the helper stops: %+v", r)
	}
	if err := c.Call(context.Background(), "system.info", struct{}{}, nil); !errors.Is(err, ErrHelperDown) {
		t.Fatalf("a new connection was taken while the helper stops: %v", err)
	}
	close(release)
	if err := <-res; err != nil {
		t.Fatalf("the change in flight failed: %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the change finished")
	}
	if !fr.has("systemctl reload nginx") {
		t.Fatalf("the reload after the test did not run: %v", fr.calls)
	}
}

// An operation still running when the grace ends is cancelled, and Serve
// returns.
func TestStopCancelsAfterTheGrace(t *testing.T) {
	h, fr, _, _ := newTest(t)
	h.StopGrace = 200 * time.Millisecond
	started, _ := blockNginxTest(h)
	c, stop, served := serveTCP(t, h)
	res := make(chan error, 1)
	go func() {
		res <- c.Call(context.Background(), "service", serviceArgs{Name: "nginx", Action: "reload"}, nil)
	}()
	<-started
	begin := time.Now()
	stop()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the grace")
	}
	if d := time.Since(begin); d < 150*time.Millisecond {
		t.Fatalf("the operation was cancelled before the grace ended (%s)", d)
	}
	if err := <-res; err == nil {
		t.Fatal("the cancelled operation reported success")
	}
	if fr.has("systemctl reload nginx") {
		t.Fatal("nginx was reloaded after its test was cancelled")
	}
}

// A change of the appliance's network that ends because the helper stops
// still brings the previous settings back: the commands of the rollback do
// not use the ended context.
func TestNetworkRollbackAfterAnInterruption(t *testing.T) {
	h, _, root, _ := newTest(t)
	_ = os.MkdirAll(filepath.Join(root, "var/lib/hostzit"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "var/lib/hostzit/.appliance"), nil, 0o644)
	o := h.Sys.(*OS)
	orig := o.Runner
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var afterStop []string
	o.Runner = func(c context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		if c.Err() != nil {
			return nil, c.Err() // like exec.CommandContext: nothing runs
		}
		line := name + " " + strings.Join(args, " ")
		if name == "ping" {
			cancel() // the helper is stopped while it waits for the gateway
			return nil, errors.New("no answer")
		}
		if ctx.Err() != nil {
			mu.Lock()
			afterStop = append(afterStop, line)
			mu.Unlock()
		}
		return orig(c, stdin, name, args...)
	}
	raw := []byte(`{"address":"192.168.1.20/24","gateway":"192.168.1.1","dns":["1.1.1.1"]}`)
	r := h.Do(ctx, Request{Op: "system.network", Args: raw})
	if r.OK || !strings.Contains(r.Error, "interrupted") {
		t.Fatalf("answer: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/network/50-hostzit.network")); !os.IsNotExist(err) {
		t.Fatalf("the new network file stayed (%v)", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(afterStop, "|") != "networkctl reload|networkctl reconfigure eth0" {
		t.Fatalf("the previous network was not applied again: %q", afterStop)
	}
}
