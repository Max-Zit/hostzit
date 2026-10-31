package helper

import (
	"context"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
)

// The account's Redis (object cache): unit, configuration and the PHP
// extension of the account's PHP versions.

// applyRedis starts, changes or removes the account's Redis.
func (h *Helper) applyRedis(ctx context.Context, a hosting.Account) error {
	unit := hosting.RedisUnitName(a.Name)
	if !a.Redis || a.Limits.RedisMB == 0 {
		if h.Sys.Exists(systemdDir + unit) {
			_ = h.systemctl(ctx, "disable", "--now", unit)
			_ = h.Sys.Remove(systemdDir + unit)
			_ = h.Sys.Remove(hosting.CageDir(a.Name) + hosting.RedisConfPath)
			_ = h.systemctl(ctx, "daemon-reload")
		}
		return nil
	}
	if !h.Sys.Exists("/usr/bin/redis-server") {
		if out, err := h.apt(ctx, "install", "--no-install-recommends", "redis-server", "redis-tools"); err != nil {
			return userErr("Redis could not be installed: " + tail(string(out), 300))
		}
		// only the accounts' own instances run
		_ = h.systemctl(ctx, "disable", "--now", "redis-server.service")
	}
	var missing []string
	for _, v := range a.PHPVersions {
		if !h.Sys.Exists("/etc/php/" + v + "/mods-available/redis.ini") {
			missing = append(missing, "php"+v+"-redis")
		}
	}
	if len(missing) > 0 {
		if out, err := h.apt(ctx, append([]string{"install", "--no-install-recommends"}, missing...)...); err != nil {
			return userErr("the PHP Redis extension could not be installed: " + tail(string(out), 300))
		}
		for _, v := range a.PHPVersions {
			_ = h.phpScanDir(a, v)
			_ = h.systemctl(ctx, "disable", "--now", "php"+v+"-fpm.service")
			if !a.Suspended {
				_ = h.systemctl(ctx, "restart", hosting.FPMUnitName(a.Name, v))
			}
		}
	}
	unitText, err := hosting.RedisUnit(a)
	if err != nil {
		return err
	}
	conf := []byte(hosting.RedisConf(a))
	confPath := hosting.CageDir(a.Name) + hosting.RedisConfPath
	old, _ := h.Sys.ReadFile(confPath)
	oldUnit, _ := h.Sys.ReadFile(systemdDir + unit)
	if err := h.Sys.WriteFile(confPath, conf, 0o644, 0, 0); err != nil {
		return err
	}
	if err := h.Sys.WriteFile(systemdDir+unit, []byte(unitText), 0o644, 0, 0); err != nil {
		return err
	}
	if string(oldUnit) != unitText {
		if err := h.systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	if a.Suspended {
		return h.systemctl(ctx, "disable", "--now", unit)
	}
	if err := h.systemctl(ctx, "enable", unit); err != nil {
		return err
	}
	if string(old) != string(conf) || string(oldUnit) != unitText {
		return h.systemctl(ctx, "restart", unit)
	}
	return h.systemctl(ctx, "start", unit)
}

// RedisInfo is the state of an account's Redis.
type RedisInfo struct {
	Active  bool   `json:"active"`
	Memory  int64  `json:"memory_b"`
	Keys    int64  `json:"keys"`
	Hits    int64  `json:"hits"`
	Misses  int64  `json:"misses"`
	Socket  string `json:"socket"`
	Version string `json:"version"`
}

type redisArgs struct {
	Account string `json:"account"`
}

func (h *Helper) redisCLI(ctx context.Context, account string, args ...string) ([]byte, error) {
	return h.Sys.Run(ctx, nil, "redis-cli", append([]string{"-s", hosting.RedisSocketHost(account)}, args...)...)
}

func (h *Helper) redisInfo(ctx context.Context, a redisArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	st := RedisInfo{Socket: hosting.RedisSocket}
	out, _ := h.Sys.Run(ctx, nil, "systemctl", "is-active", hosting.RedisUnitName(a.Account))
	st.Active = strings.TrimSpace(string(out)) == "active"
	if !st.Active {
		return st, nil
	}
	out, err := h.redisCLI(ctx, a.Account, "INFO")
	if err != nil {
		return st, nil
	}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch {
		case k == "used_memory":
			st.Memory = n
		case k == "keyspace_hits":
			st.Hits = n
		case k == "keyspace_misses":
			st.Misses = n
		case k == "redis_version":
			st.Version = v
		case strings.HasPrefix(k, "db"):
			// db0:keys=12,expires=0,avg_ttl=0
			if kv, _, ok := strings.Cut(v, ","); ok {
				if c, err := strconv.ParseInt(strings.TrimPrefix(kv, "keys="), 10, 64); err == nil {
					st.Keys += c
				}
			}
		}
	}
	return st, nil
}

func (h *Helper) redisFlush(ctx context.Context, a redisArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if out, err := h.redisCLI(ctx, a.Account, "FLUSHALL"); err != nil {
		return nil, userErr("Redis is not running: " + tail(string(out), 200))
	}
	return nil, nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["redis.info"] = op{handle(h.redisInfo), false}
		h.ops["redis.flush"] = op{handle(h.redisFlush), false}
	})
}
