package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Helper runs the operations.
type Helper struct {
	Sys System
	Log func(format string, args ...any)
	// PanelUID may connect besides root (-1 = only root).
	PanelUID int
	// WebGroup is the group of the web server (reads static files);
	// WebGID its id (looked up at start).
	WebGroup string
	WebGID   int
	// HelperBin is the path of this program (cage units, the worker).
	HelperBin string
	// PDNS reaches the PowerDNS HTTP API.
	PDNS PDNS
	// PeerCheck replaces the SO_PEERCRED check (tests).
	PeerCheck func(net.Conn) error
	// StopGrace is how long the operations in flight may still run when
	// Serve is stopped (0 = DefaultStopGrace).
	StopGrace time.Duration

	// mu serialises changes of the system configuration (nginx tests and
	// reloads, systemd, users); read-only operations run in parallel.
	mu  sync.Mutex
	ops map[string]op
	// stopping: Serve was stopped, nothing new starts
	stopping atomic.Bool
}

// DefaultStopGrace: a stop of the helper (an update restarts it, a reboot
// stops it) lets the operations in flight finish, so a change is never cut
// between writing its files, testing them and reloading the service. A cut
// there made the change count as failed and be rolled back under a service
// that was already starting: EmailZit 0.11.4 removed a new server's first
// main.cf under a starting postfix that way. systemd stops only the main
// process (KillMode=mixed in hostzit-helper.service), so the programs of
// an operation keep running too. Longer operations (a malware scan, a
// backup) are cancelled when the grace ends.
const DefaultStopGrace = 20 * time.Second

// errStopping answers what would start while the helper stops.
var errStopping = errors.New("the helper is restarting; try again in a moment")

type op struct {
	fn     func(ctx context.Context, args json.RawMessage) (any, error)
	change bool // takes the configuration lock
}

// New prepares a helper.
func New(sys System) *Helper {
	h := &Helper{Sys: sys, PanelUID: -1, WebGroup: "hostzit-web", HelperBin: "/usr/lib/hostzit/hostzit-helper"}
	h.ops = map[string]op{}
	h.register()
	return h
}

func (h *Helper) logf(format string, args ...any) {
	if h.Log != nil {
		h.Log(format, args...)
	}
}

// handle decodes args into T and calls fn.
func handle[T any](fn func(ctx context.Context, a T) (any, error)) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a T
		if len(raw) > 0 && string(raw) != "null" {
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&a); err != nil {
				return nil, userErr("invalid arguments: " + err.Error())
			}
		}
		return fn(ctx, a)
	}
}

// Ops lists the operations (documentation and tests).
func (h *Helper) Ops() []string {
	out := make([]string, 0, len(h.ops))
	for k := range h.ops {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Do runs one request.
func (h *Helper) Do(ctx context.Context, req Request) Response {
	o, ok := h.ops[req.Op]
	if !ok {
		return Response{Error: ErrUnknownOp.Error() + " " + req.Op}
	}
	if h.stopping.Load() {
		return Response{Error: errStopping.Error()}
	}
	if o.change {
		h.mu.Lock()
		defer h.mu.Unlock()
		// a change that waited for the one before it does not start once
		// the helper stops: it has changed nothing yet
		if h.stopping.Load() {
			return Response{Error: errStopping.Error()}
		}
	}
	start := time.Now()
	res, err := o.fn(ctx, req.Args)
	if err != nil {
		h.logf("op=%s req=%s by=%s failed after %s: %v", req.Op, req.ReqID, req.By, time.Since(start).Round(time.Millisecond), err)
		var ue *UserError
		if errors.As(err, &ue) {
			return Response{Error: ue.Msg}
		}
		return Response{Error: err.Error()}
	}
	if o.change {
		h.logf("op=%s req=%s by=%s done in %s", req.Op, req.ReqID, req.By, time.Since(start).Round(time.Millisecond))
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Result: raw}
}

// Serve answers connections until ctx ends or the listener closes. Then
// it takes no new connection or operation, lets the operations in flight
// finish within the stop grace (their context ends with it) and returns
// once they did, or a little after the grace at the latest.
func (h *Helper) Serve(ctx context.Context, l net.Listener) error {
	opCtx, cancelOps := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelOps()
	stopListen := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stopListen()
	var running sync.WaitGroup
	var inFlight atomic.Int64
	var err error
	for {
		c, aerr := l.Accept()
		if aerr != nil {
			if ctx.Err() == nil && !errors.Is(aerr, net.ErrClosed) {
				err = aerr
			}
			break
		}
		running.Add(1)
		inFlight.Add(1)
		go func() {
			defer running.Done()
			defer inFlight.Add(-1)
			h.serveConn(opCtx, c)
		}()
	}
	h.stopping.Store(true)
	grace := h.StopGrace
	if grace <= 0 {
		grace = DefaultStopGrace
	}
	if n := inFlight.Load(); n > 0 {
		h.logf("stopping: waiting up to %s for %d operation(s) in flight", grace, n)
	}
	ends := time.AfterFunc(grace, cancelOps)
	defer ends.Stop()
	done := make(chan struct{})
	go func() { running.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace + 10*time.Second):
		h.logf("stopping with %d operation(s) still running", inFlight.Load())
	}
	return err
}

func (h *Helper) checkPeer(c net.Conn) error {
	if h.PeerCheck != nil {
		return h.PeerCheck(c)
	}
	uid, err := peerUID(c)
	if err != nil {
		return err
	}
	if uid != 0 && uid != h.PanelUID {
		return fmt.Errorf("uid %d may not use the helper", uid)
	}
	return nil
}

func (h *Helper) serveConn(ctx context.Context, c net.Conn) {
	if err := h.checkPeer(c); err != nil {
		h.logf("connection refused: %v", err)
		_ = c.Close()
		return
	}
	h.answer(ctx, c)
}

func (h *Helper) answer(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Minute))
	line, err := bufio.NewReaderSize(io.LimitReader(c, MaxRequest), 64<<10).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	var req Request
	resp := Response{Error: "invalid request"}
	if json.Unmarshal(line, &req) == nil {
		ctx, cancel := context.WithTimeout(ctx, OpTimeout(req.Op))
		resp = h.Do(ctx, req)
		cancel()
	}
	_ = c.SetWriteDeadline(time.Now().Add(time.Minute))
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

// ScanTimeout is the longest malware scan of one account.
const ScanTimeout = 6 * time.Hour

// OpTimeout is how long one helper operation (or the job of the same
// name in the panel) may run. A malware scan of a real account takes
// longer than the usual 30 minutes: on h1 a 6.4 GB WordPress account
// (79,000 files, scanned at the lowest priority) was killed after 30
// minutes with "nice: signal: killed".
func OpTimeout(op string) time.Duration {
	if op == "malware.scan" {
		return ScanTimeout + 5*time.Minute
	}
	return 30 * time.Minute
}

// ServeConn answers one connection (in-process use in development and tests).
func (h *Helper) ServeConn(ctx context.Context, c net.Conn) { h.answer(ctx, c) }
