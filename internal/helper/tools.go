package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/max-zit/hostzit/internal/hosting"
)

type cronArgs struct {
	Account string            `json:"account"`
	Jobs    []hosting.CronJob `json:"jobs"`
}

// cronApply makes the account's timers match the list. The command goes
// into ~/.hz-cron/<id>.sh, written by the worker as the account; the units
// only name that file.
func (h *Helper) cronApply(ctx context.Context, a cronArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if len(a.Jobs) > 100 {
		return nil, userErr("at most 100 scheduled jobs per account")
	}
	want := map[string]bool{}
	type unitPair struct{ svc, tmr string }
	units := map[int64]unitPair{}
	scripts := map[string]string{}
	for _, j := range a.Jobs {
		if err := hosting.CheckCommand(j.Command); err != nil {
			return nil, userErr(err.Error())
		}
		svc, tmr, err := hosting.CronUnits(a.Account, j)
		if err != nil {
			return nil, userErr(err.Error())
		}
		units[j.ID] = unitPair{svc, tmr}
		scripts[strconv.FormatInt(j.ID, 10)+".sh"] = "#!/bin/bash\n# written by the HostZit panel: scheduled job " + strconv.FormatInt(j.ID, 10) + "\n" + j.Command + "\n"
	}
	// all scripts in one worker run (one per file made 140 runs for 70 jobs)
	data, _ := json.Marshal(scripts)
	if _, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "cron-scripts", Path: ".hz-cron", Data: data}}); err != nil {
		return nil, err
	}
	for _, j := range a.Jobs {
		svc, tmr := units[j.ID].svc, units[j.ID].tmr
		name := fmt.Sprintf("hz-cron-%s-%d", a.Account, j.ID)
		if err := h.Sys.WriteFile(systemdDir+name+".service", []byte(svc), 0o644, 0, 0); err != nil {
			return nil, err
		}
		if err := h.Sys.WriteFile(systemdDir+name+".timer", []byte(tmr), 0o644, 0, 0); err != nil {
			return nil, err
		}
		want[name] = j.Enabled
	}
	ents, _ := h.Sys.ReadDir(systemdDir)
	prefix := "hz-cron-" + a.Account + "-"
	for _, e := range ents {
		n := e.Name()
		base := strings.TrimSuffix(strings.TrimSuffix(n, ".timer"), ".service")
		if !strings.HasPrefix(n, prefix) {
			continue
		}
		if _, ok := want[base]; !ok {
			if strings.HasSuffix(n, ".timer") {
				_ = h.systemctl(ctx, "disable", "--now", n)
			}
			_ = h.Sys.Remove(systemdDir + n)
		}
	}
	if err := h.systemctl(ctx, "daemon-reload"); err != nil {
		return nil, err
	}
	// one systemctl call for all timers to start and one for all to stop:
	// each call reloads systemd, one per job made an account with many
	// jobs hold the helper for a minute on every change
	var on, off []string
	for name, enabled := range want {
		if enabled {
			on = append(on, name+".timer")
		} else {
			off = append(off, name+".timer")
		}
	}
	slices.Sort(on)
	slices.Sort(off)
	if len(on) > 0 {
		if err := h.systemctl(ctx, append([]string{"enable", "--now"}, on...)...); err != nil {
			return nil, err
		}
	}
	if len(off) > 0 {
		_ = h.systemctl(ctx, append([]string{"disable", "--now"}, off...)...)
	}
	return map[string]int{"jobs": len(want)}, nil
}

type cronRef struct {
	Account string `json:"account"`
	ID      int64  `json:"id"`
}

func (r cronRef) unit() (string, error) {
	if err := hosting.ValidAccount(r.Account); err != nil {
		return "", userErr(err.Error())
	}
	if r.ID <= 0 {
		return "", userErr("job id missing")
	}
	return fmt.Sprintf("hz-cron-%s-%d.service", r.Account, r.ID), nil
}

func (h *Helper) cronRun(ctx context.Context, r cronRef) (any, error) {
	u, err := r.unit()
	if err != nil {
		return nil, err
	}
	if !h.Sys.Exists(systemdDir + u) {
		return nil, userErr("no such job")
	}
	return nil, h.systemctl(ctx, "start", "--no-block", u)
}

func (h *Helper) cronLog(ctx context.Context, r cronRef) (any, error) {
	u, err := r.unit()
	if err != nil {
		return nil, err
	}
	out, _ := h.Sys.Run(ctx, nil, "journalctl", "-u", u, "-n", "60", "--no-pager", "-o", "short-iso", "-q")
	return map[string]string{"text": tail(string(out), 20000)}, nil
}

type keysArgs struct {
	Account string   `json:"account"`
	Keys    []string `json:"keys"`
}

// CheckSSHKey parses one public key and returns it without options.
func CheckSSHKey(k string) (string, string, error) {
	pk, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(k)))
	if err != nil || len(opts) > 0 {
		return "", "", fmt.Errorf("not a public SSH key (one line, e.g. ssh-ed25519 AAAA… name)")
	}
	switch pk.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
	default:
		return "", "", fmt.Errorf("the key type %s is not allowed", pk.Type())
	}
	if pk.Type() == ssh.KeyAlgoRSA {
		if ck, ok := pk.(ssh.CryptoPublicKey); ok {
			if rk, ok := ck.CryptoPublicKey().(interface{ Size() int }); ok && rk.Size() < 256 {
				return "", "", fmt.Errorf("RSA keys need at least 2048 bits")
			}
		}
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	comment = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, comment)
	if comment != "" {
		line += " " + comment
	}
	return line, ssh.FingerprintSHA256(pk), nil
}

// sshKeys writes ~/.ssh/authorized_keys as the account.
func (h *Helper) sshKeys(ctx context.Context, a keysArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if len(a.Keys) > 50 {
		return nil, userErr("at most 50 keys")
	}
	var b strings.Builder
	b.WriteString("# managed by the HostZit panel; changes here are replaced\n")
	for _, k := range a.Keys {
		line, _, err := CheckSSHKey(k)
		if err != nil {
			return nil, userErr(err.Error())
		}
		b.WriteString(line + "\n")
	}
	if _, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "write", Path: ".ssh/authorized_keys", Data: []byte(b.String())}}); err != nil {
		return nil, err
	}
	_, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "chmod", Path: ".ssh/authorized_keys", Mode: "600"}})
	return nil, err
}
