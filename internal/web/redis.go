package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/hosting"
	"github.com/max-zit/hostzit/internal/store"
)

// The account's Redis object cache: the customer switches it on under PHP
// (when the package gives Redis memory) and connects WordPress sites to it
// with one click (plugin "Redis Object Cache").

func init() {
	customerExtra = append(customerExtra, func(s *Server, mux *http.ServeMux, c func(string, http.HandlerFunc)) {
		c("POST /redis", s.handleRedisSwitch)
		c("POST /redis/flush", s.handleRedisFlush)
		c("POST /wordpress/{id}/redis", s.handleWPRedis)
	})
}

func redisKey(c *store.Customer) string { return "redis:" + strconv.FormatInt(c.ID, 10) }

// redisOn reports the customer's switch.
func (s *Server) redisOn(ctx context.Context, c *store.Customer) bool {
	var on bool
	_ = s.store.GetSetting(ctx, redisKey(c), &on)
	return on
}

// redisData is shown on the customer's PHP page.
type redisData struct {
	MB   int // package memory (0 = no Redis)
	On   bool
	Info helper.RedisInfo
}

func (s *Server) redisState(ctx context.Context, by string, c *store.Customer, l hosting.Limits) *redisData {
	d := &redisData{MB: l.RedisMB, On: l.RedisMB > 0 && s.redisOn(ctx, c)}
	if d.On {
		_ = s.call(ctx, by, "redis.info", map[string]string{"account": c.Username}, &d.Info)
	}
	return d
}

func (s *Server) handleRedisSwitch(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	a, _, err := s.accountFor(r.Context(), c)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	on := r.FormValue("on") == "1"
	if on && a.Limits.RedisMB == 0 {
		s.redirectErr(w, r, "/php", "Your package has no Redis.")
		return
	}
	if err := s.store.SetSetting(r.Context(), redisKey(c), on); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "redis.switch", "customer:"+c.Username, "Redis on: %v", on)
	if err := s.applyCustomer(r.Context(), actor(r), c); err != nil {
		s.redirectErr(w, r, "/php", storeErr(err))
		return
	}
	if on {
		s.redirect(w, r, "/php", "Redis is running.")
		return
	}
	s.redirect(w, r, "/php", "Redis is off.")
}

func (s *Server) handleRedisFlush(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	if err := s.call(r.Context(), actor(r), "redis.flush", map[string]string{"account": c.Username}, nil); err != nil {
		s.redirectErr(w, r, "/php", storeErr(err))
		return
	}
	s.audit(r, "redis.flush", "customer:"+c.Username, "Redis emptied")
	s.redirect(w, r, "/php", "Redis was emptied.")
}

// handleWPRedis connects a WordPress site to the account's Redis (on=1) or
// back to no object cache.
func (s *Server) handleWPRedis(w http.ResponseWriter, r *http.Request) {
	c := s.me(w, r)
	if c == nil {
		return
	}
	in := s.myWP(w, r, c)
	if in == nil {
		return
	}
	back := "/wordpress/" + strconv.FormatInt(in.ID, 10)
	ctx, by := r.Context(), actor(r)
	run := func(args ...string) error {
		_, err := s.wpcli(ctx, by, c.Username, in.Path, "", args...)
		return err
	}
	var errs []error
	if r.FormValue("on") == "1" {
		if !s.redisOn(ctx, c) {
			s.redirectErr(w, r, back, "Switch Redis on under PHP first.")
			return
		}
		for _, kv := range [][2]string{{"WP_REDIS_SCHEME", "unix"}, {"WP_REDIS_PATH", hosting.RedisSocket}, {"WP_REDIS_PREFIX", in.Domain + ":"}} {
			errs = append(errs, run("config", "set", kv[0], kv[1], "--type=constant"))
		}
		if err := run("plugin", "is-installed", "redis-cache"); err != nil {
			errs = append(errs, run("plugin", "install", "redis-cache"))
		}
		errs = append(errs, run("plugin", "activate", "redis-cache"), run("redis", "enable", "--force"))
	} else {
		_ = run("redis", "disable")
		errs = append(errs, run("plugin", "deactivate", "redis-cache"))
	}
	s.audit(r, "wp.redis", "site:"+in.Domain, "Redis object cache: %v", r.FormValue("on") == "1")
	if err := errors.Join(errs...); err != nil {
		s.redirectErr(w, r, back, storeErr(err))
		return
	}
	s.redirect(w, r, back, "Saved.")
}
