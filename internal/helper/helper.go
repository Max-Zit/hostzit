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

	// mu serialises changes of the system configuration (nginx tests and
	// reloads, systemd, users); read-only operations run in parallel.
	mu  sync.Mutex
	ops map[string]op
}

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
	if o.change {
		h.mu.Lock()
		defer h.mu.Unlock()
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

// Serve answers connections until the listener closes.
func (h *Helper) Serve(ctx context.Context, l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go h.serveConn(ctx, c)
	}
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
		ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		resp = h.Do(ctx, req)
		cancel()
	}
	_ = c.SetWriteDeadline(time.Now().Add(time.Minute))
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

// ServeConn answers one connection (in-process use in development and tests).
func (h *Helper) ServeConn(ctx context.Context, c net.Conn) { h.answer(ctx, c) }
