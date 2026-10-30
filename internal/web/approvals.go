package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/max-zit/hostzit/internal/store"
)

// Four-eyes approval: with the setting on, deleting or terminating a
// customer and deleting a package wait until a second administrator
// approves them.

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("GET /approvals", s.handleApprovals)
		admin("POST /approvals/{id}/approve", s.handleApprovalDecide(true))
		admin("POST /approvals/{id}/reject", s.handleApprovalDecide(false))
	})
}

// fourEyes reports whether an action must wait for a second administrator.
func (s *Server) fourEyes(ctx context.Context) bool { return s.security(ctx).FourEyes }

// askApproval stores the request and tells the administrator.
func (s *Server) askApproval(w http.ResponseWriter, r *http.Request, back, action, target, summary string, params map[string]string) {
	a := &store.Approval{Action: action, Target: target, Summary: summary, Params: params, RequestedBy: userFrom(r).Username}
	if err := s.store.RequestApproval(r.Context(), a); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.audit(r, "approval.request", target, "%s: %s", action, summary)
	s.notify(r.Context(), "approval:"+strconv.FormatInt(a.ID, 10), nil, "HostZit: approval needed", userFrom(r).Username+" asks for: "+summary+"\n\nApprove or reject it in the admin panel under Approvals.\n")
	s.redirect(w, r, back, "A second administrator must approve this. It is listed under Approvals.")
}

// runApproved does an approved action.
func (s *Server) runApproved(ctx context.Context, by string, a *store.Approval) error {
	switch a.Action {
	case "customer.delete", "customer.terminate":
		id, _ := strconv.ParseInt(a.Params["customer"], 10, 64)
		c, err := s.store.CustomerByID(ctx, id)
		if err != nil {
			return err
		}
		if a.Action == "customer.delete" {
			return s.deleteAccount(ctx, by, c)
		}
		return s.setStatus(ctx, by, c, store.StatusTerminated, a.Params["reason"])
	case "package.delete":
		id, _ := strconv.ParseInt(a.Params["package"], 10, 64)
		return s.store.DeletePackage(ctx, id)
	}
	return errors.New("unknown action")
}

type approvalsData struct {
	List []*store.Approval
	Me   string
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Approvals(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "approvals", &Page{Title: "Approvals", Nav: "approvals", Data: &approvalsData{List: list, Me: userFrom(r).Username}})
}

func (s *Server) handleApprovalDecide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := pathID(r, "id")
		by := userFrom(r).Username
		a, err := s.store.DecideApproval(r.Context(), id, by, approve)
		if err != nil {
			s.redirectErr(w, r, "/approvals", storeErr(err))
			return
		}
		if !approve {
			s.audit(r, "approval.reject", a.Target, "%s rejected (asked by %s)", a.Summary, a.RequestedBy)
			s.redirect(w, r, "/approvals", "Rejected.")
			return
		}
		err = s.runApproved(r.Context(), by+" (approved, asked by "+a.RequestedBy+")", a)
		_ = s.store.FinishApproval(r.Context(), a.ID, err)
		s.audit(r, "approval.approve", a.Target, "%s approved (asked by %s): %v", a.Summary, a.RequestedBy, errText(err))
		if err != nil {
			s.redirectErr(w, r, "/approvals", storeErr(err))
			return
		}
		s.redirect(w, r, "/approvals", "Approved and done.")
	}
}

func errText(err error) string {
	if err == nil {
		return "done"
	}
	return err.Error()
}
