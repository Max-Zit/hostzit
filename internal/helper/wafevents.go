package helper

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Firewall events of a site from ModSecurity's audit log (serial format:
// part A = time, id and client, B = request line and headers, H = the
// matched rules). Only requests to the site's own names are returned.

const modsecAuditLog = "/var/log/hostzit/modsec_audit.log"

// WAFRule is a rule that matched.
type WAFRule struct {
	ID  int    `json:"id"`
	Msg string `json:"msg"`
}

// WAFEvent is a request the firewall blocked or, in detection mode,
// would have blocked.
type WAFEvent struct {
	Time    string    `json:"time"`
	Client  string    `json:"client"`
	Request string    `json:"request"`
	Blocked bool      `json:"blocked"`
	Rules   []WAFRule `json:"rules"`
}

type wafEventsArgs struct {
	Account string   `json:"account"`
	ID      int64    `json:"id"`
	Names   []string `json:"names"` // host names of the site
	Max     int      `json:"max"`
}

var (
	auditBoundaryRE = regexp.MustCompile(`^---[A-Za-z0-9]+---([A-Z])--$`)
	auditTagRE      = regexp.MustCompile(`\[(id|msg) "([^"]*)"\]`)
)

// wafSummaryRules only add up the scores of the others.
var wafSummaryRules = []int{949110, 959100, 980130, 980140, 980170, 980180}

// parseAudit returns the events for the given hosts, newest first.
func parseAudit(text string, hosts []string, max int) []WAFEvent {
	var out []WAFEvent
	var cur *WAFEvent
	var host, part string
	flush := func() {
		if cur != nil && slices.Contains(hosts, host) && len(cur.Rules)+boolInt(cur.Blocked) > 0 {
			out = append(out, *cur)
		}
		cur, host = nil, ""
	}
	for _, line := range strings.Split(text, "\n") {
		if m := auditBoundaryRE.FindStringSubmatch(line); m != nil {
			part = m[1]
			switch part {
			case "A":
				flush()
				cur = &WAFEvent{}
			case "Z":
				flush()
			}
			continue
		}
		if cur == nil || line == "" {
			continue
		}
		switch part {
		case "A":
			// [31/Oct/2026:22:24:00 +0000] 179348544055.968850 127.0.0.1 50838 127.0.0.1 80
			if t, rest, ok := strings.Cut(strings.TrimPrefix(line, "["), "] "); ok {
				cur.Time = t
				if f := strings.Fields(rest); len(f) > 1 {
					cur.Client = f[1]
				}
			}
		case "B":
			if cur.Request == "" {
				cur.Request = line
			} else if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(k, "host") {
				h := strings.ToLower(strings.TrimSpace(v))
				if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "]") {
					h = h[:i]
				}
				host = h
			}
		case "H":
			if !strings.HasPrefix(line, "ModSecurity: ") {
				continue
			}
			if strings.HasPrefix(line, "ModSecurity: Access denied") {
				cur.Blocked = true
			}
			var r WAFRule
			for _, m := range auditTagRE.FindAllStringSubmatch(line, -1) {
				if m[1] == "id" {
					r.ID, _ = strconv.Atoi(m[2])
				} else {
					r.Msg = m[2]
				}
			}
			if r.ID > 0 && !slices.Contains(wafSummaryRules, r.ID) && !slices.ContainsFunc(cur.Rules, func(x WAFRule) bool { return x.ID == r.ID }) {
				cur.Rules = append(cur.Rules, r)
			}
		}
	}
	flush()
	slices.Reverse(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (h *Helper) wafEvents(ctx context.Context, a wafEventsArgs) (any, error) {
	if err := (siteRef{Account: a.Account, ID: a.ID}).check(); err != nil {
		return nil, err
	}
	if len(a.Names) == 0 || len(a.Names) > 50 {
		return nil, userErr("invalid site names")
	}
	hosts := make([]string, 0, len(a.Names))
	for _, n := range a.Names {
		n = strings.ToLower(n)
		if !hosting.ValidDomain(n) {
			return nil, userErr("invalid site name")
		}
		hosts = append(hosts, n)
	}
	if a.Max < 1 || a.Max > 200 {
		a.Max = 30
	}
	b, err := h.Sys.Run(ctx, nil, "tail", "-c", "8388608", modsecAuditLog)
	if err != nil {
		return []WAFEvent{}, nil
	}
	// yesterday's log too (rotated each night, compressed only a day later)
	if h.Sys.Exists(modsecAuditLog + ".1") {
		if old, err := h.Sys.Run(ctx, nil, "tail", "-c", "4194304", modsecAuditLog+".1"); err == nil {
			b = append(old, b...)
		}
	}
	return parseAudit(string(b), hosts, a.Max), nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["waf.events"] = op{handle(h.wafEvents), false}
	})
}
