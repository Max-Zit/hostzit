// Package helper is the root side of HostZit. The panel runs as the
// unprivileged hostzit user and asks for every privileged change over the
// Unix socket /run/hostzit/helper.sock: one JSON request per connection,
// one JSON answer. Only root and the hostzit user may connect (checked
// with SO_PEERCRED on every connection).
//
// The helper trusts nothing beyond the wish itself. Every operation is on
// an allow-list, its arguments are typed and validated again here, and all
// configuration files are rendered by the helper from its own templates
// (package hosting) — the panel never sends file contents or commands.
// Work inside an account's files is done by a worker that runs as that
// account, inside its cage, so root never follows a path the account
// controls.
package helper

import (
	"encoding/json"
	"errors"
)

// SocketPath is where the helper listens.
const SocketPath = "/run/hostzit/helper.sock"

// Request is one call.
type Request struct {
	Op    string          `json:"op"`
	ReqID string          `json:"req_id,omitempty"` // the panel's request id (logs)
	By    string          `json:"by,omitempty"`     // who asked (logs)
	Args  json.RawMessage `json:"args,omitempty"`
}

// Response is the answer.
type Response struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// MaxRequest is the largest request (file uploads go up to 48 MB base64).
const MaxRequest = 72 << 20

// ErrUnknownOp is returned for an operation that is not on the list.
var ErrUnknownOp = errors.New("unknown operation")

// UserError is an error whose message may be shown to the user.
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

func userErr(msg string) error { return &UserError{Msg: msg} }
