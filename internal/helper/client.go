package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Client calls the helper (the panel's side).
type Client struct {
	Path string
	// Dial replaces the socket connection (tests run the helper in-process).
	Dial func(ctx context.Context) (net.Conn, error)
}

// ErrHelperDown means the helper socket is not reachable.
var ErrHelperDown = errors.New("the HostZit root helper is not running")

// Call runs an operation; result may be nil.
func (c *Client) Call(ctx context.Context, op string, args, result any) error {
	return c.CallAs(ctx, "", "", op, args, result)
}

// CallAs runs an operation and names who asked and the request id.
func (c *Client) CallAs(ctx context.Context, by, reqID, op string, args, result any) error {
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	req, err := json.Marshal(Request{Op: op, ReqID: reqID, By: by, Args: raw})
	if err != nil {
		return err
	}
	var conn net.Conn
	if c.Dial != nil {
		conn, err = c.Dial(ctx)
	} else {
		var d net.Dialer
		path := c.Path
		if path == "" {
			path = SocketPath
		}
		conn, err = d.DialContext(ctx, "unix", path)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHelperDown, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	}
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return err
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return fmt.Errorf("helper answer: %w", err)
	}
	if !resp.OK {
		return &UserError{Msg: resp.Error}
	}
	if result != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, result)
	}
	return nil
}
