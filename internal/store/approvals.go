package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Approval is an action waiting for a second administrator.
type Approval struct {
	ID          int64
	Action      string
	Target      string
	Summary     string
	Params      map[string]string
	RequestedBy string
	RequestedAt time.Time
	Status      string
	DecidedBy   string
	DecidedAt   *time.Time
	Result      string
}

// RequestApproval stores a pending action (one per action and target).
func (s *Store) RequestApproval(ctx context.Context, a *Approval) error {
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE status='pending' AND action=$1 AND target=$2`, a.Action, a.Target).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("this action is already waiting for approval")
	}
	p, _ := json.Marshal(a.Params)
	return s.db.QueryRow(ctx, `INSERT INTO approvals(action, target, summary, params, requested_by, requested_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
		a.Action, a.Target, truncate(a.Summary, 300), p, a.RequestedBy, s.now()).Scan(&a.ID)
}

// Approvals lists pending first, then the newest decided ones.
func (s *Store) Approvals(ctx context.Context) ([]*Approval, error) {
	rows, err := s.db.Query(ctx, `SELECT id, action, target, summary, params, requested_by, requested_at, status, decided_by, decided_at, result FROM approvals
		ORDER BY (status='pending') DESC, requested_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Approval
	for rows.Next() {
		a := &Approval{}
		var p []byte
		if err := rows.Scan(&a.ID, &a.Action, &a.Target, &a.Summary, &p, &a.RequestedBy, &a.RequestedAt, &a.Status, &a.DecidedBy, &a.DecidedAt, &a.Result); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(p, &a.Params)
		out = append(out, a)
	}
	return out, rows.Err()
}

// DecideApproval marks a pending approval approved or rejected by someone
// other than the requester; it returns the approval.
func (s *Store) DecideApproval(ctx context.Context, id int64, by string, approve bool) (*Approval, error) {
	st := "rejected"
	if approve {
		st = "approved"
	}
	tag, err := s.db.Exec(ctx, `UPDATE approvals SET status=$3, decided_by=$2, decided_at=$4 WHERE id=$1 AND status='pending' AND requested_by<>$2`, id, by, st, s.now())
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, errors.New("the approval is not pending, or you asked for it yourself")
	}
	list, err := s.Approvals(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range list {
		if a.ID == id {
			return a, nil
		}
	}
	return nil, ErrNotFound
}

// FinishApproval stores the outcome of the approved action.
func (s *Store) FinishApproval(ctx context.Context, id int64, actionErr error) error {
	st, res := "done", ""
	if actionErr != nil {
		st, res = "failed", truncate(actionErr.Error(), 500)
	}
	_, err := s.db.Exec(ctx, `UPDATE approvals SET status=$2, result=$3 WHERE id=$1`, id, st, res)
	return err
}

// PendingApprovals counts the open ones (sidebar badge).
func (s *Store) PendingApprovals(ctx context.Context) int {
	var n int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE status='pending'`).Scan(&n)
	return n
}
