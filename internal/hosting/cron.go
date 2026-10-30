package hosting

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// CronJob is a scheduled command of an account. The command is written by
// the account itself into a script inside its home and run as the account
// in its cage, so it never reaches a unit file.
type CronJob struct {
	ID       int64  `json:"id"`
	Schedule string `json:"schedule"` // cron syntax: minute hour day month weekday
	Command  string `json:"command"`
	Enabled  bool   `json:"enabled"`
}

var cronFieldRE = regexp.MustCompile(`^(\*|[0-9]+(-[0-9]+)?)(/[0-9]+)?(,(\*|[0-9]+(-[0-9]+)?)(/[0-9]+)?)*$`)

var cronMacros = map[string]string{"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *"}

var dayNames = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

func cronField(f string, lo, hi int, dow bool) (string, error) {
	if !cronFieldRE.MatchString(f) {
		return "", fmt.Errorf("%q is not a cron field", f)
	}
	var parts []string
	for _, p := range strings.Split(f, ",") {
		step := ""
		if i := strings.IndexByte(p, '/'); i >= 0 {
			n, _ := strconv.Atoi(p[i+1:])
			if n < 1 || n > hi {
				return "", fmt.Errorf("invalid step in %q", f)
			}
			step, p = "/"+strconv.Itoa(n), p[:i]
		}
		if p == "*" {
			if step == "" {
				parts = append(parts, "*")
				continue
			}
			p = strconv.Itoa(lo)
			if dow {
				return "", errors.New("steps over weekdays are not supported")
			}
			parts = append(parts, p+step)
			continue
		}
		a, b, rng := strings.Cut(p, "-")
		x, _ := strconv.Atoi(a)
		y := x
		if rng {
			y, _ = strconv.Atoi(b)
		}
		if x < lo || y > hi || y < x {
			return "", fmt.Errorf("%q is outside %d–%d", p, lo, hi)
		}
		if dow {
			if step != "" {
				return "", errors.New("steps over weekdays are not supported")
			}
			if rng {
				parts = append(parts, dayNames[x]+".."+dayNames[y])
			} else {
				parts = append(parts, dayNames[x])
			}
			continue
		}
		v := strconv.Itoa(x)
		if rng {
			v += ".." + strconv.Itoa(y)
		}
		parts = append(parts, v+step)
	}
	return strings.Join(parts, ","), nil
}

// OnCalendar converts a cron schedule into a systemd calendar expression.
func OnCalendar(cron string) (string, error) {
	cron = strings.TrimSpace(cron)
	if m, ok := cronMacros[cron]; ok {
		cron = m
	}
	f := strings.Fields(cron)
	if len(f) != 5 {
		return "", errors.New("the schedule needs 5 fields: minute hour day month weekday (e.g. */15 * * * *)")
	}
	min, err := cronField(f[0], 0, 59, false)
	if err != nil {
		return "", err
	}
	hour, err := cronField(f[1], 0, 23, false)
	if err != nil {
		return "", err
	}
	dom, err := cronField(f[2], 1, 31, false)
	if err != nil {
		return "", err
	}
	mon, err := cronField(f[3], 1, 12, false)
	if err != nil {
		return "", err
	}
	out := ""
	if f[4] != "*" {
		dow, err := cronField(f[4], 0, 7, true)
		if err != nil {
			return "", err
		}
		out = dow + " "
	}
	return out + "*-" + mon + "-" + dom + " " + hour + ":" + min + ":00", nil
}

// CheckCommand checks a cron command (one line).
func CheckCommand(c string) error {
	if strings.TrimSpace(c) == "" || len(c) > 2000 || strings.ContainsAny(c, "\r\n\x00") {
		return errors.New("the command must be one line of up to 2000 characters")
	}
	return nil
}

// CronUnits renders the service and the timer of a job.
func CronUnits(account string, j CronJob) (service, timer string, err error) {
	if err := ValidAccount(account); err != nil {
		return "", "", err
	}
	cal, err := OnCalendar(j.Schedule)
	if err != nil {
		return "", "", err
	}
	if j.ID <= 0 {
		return "", "", errors.New("job id missing")
	}
	name := fmt.Sprintf("hz-cron-%s-%d", account, j.ID)
	service = fmt.Sprintf(`# HostZit (generated, do not edit)
[Unit]
Description=Scheduled job %[2]d of hosting account %[1]s
After=%[3]s
Requires=%[3]s

[Service]
Type=oneshot
User=%[1]s
Group=%[1]s
Slice=%[4]s
RootDirectory=%[5]s
MountAPIVFS=yes
BindPaths=-/run/mysqld -/run/emailzit/submit.sock
ProtectProc=invisible
ProcSubset=pid
PrivateDevices=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
RestrictNamespaces=yes
LockPersonality=yes
WorkingDirectory=%[6]s
Environment=HOME=%[6]s TMPDIR=/tmp PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=/bin/bash %[6]s/.hz-cron/%[2]d.sh
TimeoutStartSec=6h
`, account, j.ID, CageUnitName(account), SliceName(account), CageDir(account), HomeDir(account))
	timer = fmt.Sprintf("# HostZit (generated, do not edit)\n[Unit]\nDescription=Schedule of job %d of %s\n\n[Timer]\nOnCalendar=%s\nAccuracySec=30s\nUnit=%s.service\n\n[Install]\nWantedBy=timers.target\n", j.ID, account, cal, name)
	return service, timer, nil
}
