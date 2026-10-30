package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/store"
)

type usersData struct {
	Users    []*store.User // active
	Disabled []*store.User
	Form     store.NewUser
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	s.showUsers(w, r, http.StatusOK, &usersData{Form: store.NewUser{Role: store.RoleOperator}}, "")
}

func (s *Server) showUsers(w http.ResponseWriter, r *http.Request, status int, d *usersData, errMsg string) {
	all, err := s.store.Users(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Users, d.Disabled = nil, nil
	for _, u := range all {
		if u.Disabled {
			d.Disabled = append(d.Disabled, u)
		} else {
			d.Users = append(d.Users, u)
		}
	}
	p := &Page{Title: "Users", Nav: "users", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "users", p)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	n := store.NewUser{
		Username: r.FormValue("username"), DisplayName: r.FormValue("display_name"), Password: r.FormValue("password"),
		Role:               r.FormValue("role"),
		MustChangePassword: true,
	}
	u, err := s.store.CreateUser(r.Context(), n)
	if err != nil {
		n.Password = ""
		s.showUsers(w, r, http.StatusBadRequest, &usersData{Form: n}, storeErr(err))
		return
	}
	s.audit(r, "user.create", "user:"+u.Username, "created user %q with role %s", u.Username, u.Role)
	s.redirect(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "User created. Give them the password; they must change it and set up two-factor sign-in at the first sign-in.")
}

type userData struct {
	U    *store.User
	Self bool
}

func (s *Server) loadUser(w http.ResponseWriter, r *http.Request) *store.User {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	u, err := s.store.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return u
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	if u := s.loadUser(w, r); u != nil {
		s.showUser(w, r, http.StatusOK, u, "")
	}
}

func (s *Server) showUser(w http.ResponseWriter, r *http.Request, status int, u *store.User, errMsg string) {
	p := &Page{Title: u.Username, Nav: "users", Data: &userData{U: u, Self: u.ID == userFrom(r).ID}}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "user", p)
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	u := s.loadUser(w, r)
	if u == nil {
		return
	}
	role, disabled := r.FormValue("role"), r.FormValue("disabled") == "1"
	if u.ID == userFrom(r).ID {
		disabled = false
	}
	if err := s.store.UpdateUser(r.Context(), u.ID, r.FormValue("display_name"), role, disabled); err != nil {
		s.showUser(w, r, http.StatusBadRequest, u, storeErr(err))
		return
	}
	s.audit(r, "user.update", "user:"+u.Username, "role %s, disabled %v", role, disabled)
	s.redirect(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "Saved.")
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	u := s.loadUser(w, r)
	if u == nil {
		return
	}
	if err := s.store.SetPassword(r.Context(), u.ID, r.FormValue("password"), true, ""); err != nil {
		s.showUser(w, r, http.StatusBadRequest, u, storeErr(err))
		return
	}
	s.audit(r, "user.password", "user:"+u.Username, "password set by an administrator; all sessions of the user ended")
	s.redirect(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "Password set. The user must change it at the next sign-in.")
}

func (s *Server) handleUserReset2FA(w http.ResponseWriter, r *http.Request) {
	u := s.loadUser(w, r)
	if u == nil {
		return
	}
	if u.ID == userFrom(r).ID {
		s.showUser(w, r, http.StatusBadRequest, u, "You cannot reset your own two-factor sign-in; ask another administrator.")
		return
	}
	if err := s.store.ResetTwoFactor(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "2fa.reset", "user:"+u.Username, "two-factor sign-in reset by an administrator")
	s.redirect(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "Two-factor sign-in reset. The user sets it up again at the next sign-in.")
}

// ---- own account

type accountData struct {
	Sessions []store.Session
	Current  string
	Codes    []string
	Tokens   []store.APIToken
	NewToken string // shown once after it is created
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	s.showAccount(w, r, http.StatusOK, &accountData{}, "")
}

func (s *Server) showAccount(w http.ResponseWriter, r *http.Request, status int, d *accountData, errMsg string) {
	u := userFrom(r)
	list, err := s.store.UserSessions(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Sessions, d.Current = list, sessionFrom(r).Hash
	if d.Tokens, err = s.store.APITokens(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	p := &Page{Title: "My account", Nav: "account", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, u), errMsg)
	}
	s.render(w, r, status, "account", p)
}

func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if _, err := s.store.CheckPassword(r.Context(), u.Username, r.FormValue("current")); err != nil {
		s.guard.fail(r.Context(), clientIP(r), u.Username, "password change")
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, "The current password is wrong.")
		return
	}
	if r.FormValue("password") != r.FormValue("password2") {
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, "The passwords do not match.")
		return
	}
	if r.FormValue("password") == r.FormValue("current") {
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, "The new password must be different.")
		return
	}
	if err := s.store.SetPassword(r.Context(), u.ID, r.FormValue("password"), false, sessionFrom(r).Hash); err != nil {
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, storeErr(err))
		return
	}
	s.audit(r, "account.password", "user:"+u.Username, "password changed; other sessions ended")
	s.redirect(w, r, "/account", "Password changed. Your other sessions were signed out.")
}

// handleAccountRecovery makes new recovery codes; it needs a current
// authenticator code, so a forgotten open browser is not enough.
func (s *Server) handleAccountRecovery(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	tf, err := s.store.GetTwoFactor(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	step, ok := auth.TOTPVerify(tf.Secret, r.FormValue("code"), s.now(), tf.LastStep)
	if ok {
		ok, _ = s.store.UseTOTPStep(r.Context(), u.ID, step)
	}
	if !ok {
		s.guard.fail(r.Context(), clientIP(r), u.Username, "recovery codes")
		s.showAccount(w, r, http.StatusBadRequest, &accountData{}, "The code is wrong or was already used.")
		return
	}
	plain, hashed := auth.NewRecoveryCodes()
	if err := s.store.SetRecoveryCodes(r.Context(), u.ID, hashed); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "2fa.recovery", "user:"+u.Username, "new recovery codes made; the old ones no longer work")
	s.showAccount(w, r, http.StatusOK, &accountData{Codes: plain}, "")
}

func (s *Server) handleAccountSignout(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	list, err := s.store.UserSessions(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	cur := sessionFrom(r).Hash
	n := 0
	for _, x := range list {
		if x.Hash != cur {
			_ = s.store.DeleteSession(r.Context(), x.Hash)
			n++
		}
	}
	s.audit(r, "account.signout", "user:"+u.Username, "signed out %d other sessions", n)
	s.redirect(w, r, "/account", "Your other sessions were signed out.")
}

// userTable is the argument of the usertable template.
type userTable struct {
	P     *Page
	Users []*store.User
}

func init() {
	funcs["userTable"] = func(p *Page, us []*store.User) userTable { return userTable{P: p, Users: us} }
}
