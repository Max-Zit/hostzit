package web

import (
	"context"

	"github.com/max-zit/hostzit/internal/store"
)

// customer2FARequired: a customer must use two-factor sign-in when the
// server requires it for every customer (Settings → Sign-in and security)
// or the customer's package does.
func (s *Server) customer2FARequired(ctx context.Context, u *store.User) bool {
	if s.security(ctx).Customer2FA {
		return true
	}
	if !u.IsCustomer() {
		return false
	}
	c, err := s.store.CustomerByID(ctx, *u.CustomerID)
	if err != nil {
		return false
	}
	p, err := s.store.PackageByID(ctx, c.PackageID)
	return err == nil && p.Limits.TwoFactor
}
