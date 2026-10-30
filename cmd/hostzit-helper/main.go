// hostzit-helper is the root helper of HostZit (see package helper).
//
//	hostzit-helper                  serve the panel on /run/hostzit/helper.sock
//	hostzit-helper setup            prepare the system (groups, folders, nginx, SSH)
//	hostzit-helper call OP [JSON]   run one operation (administrators, scripts)
//	hostzit-helper cage-mount NAME  mount an account's cage (hz-cage-NAME.service)
//	hostzit-helper cage-umount NAME
//	hostzit-helper files-worker     file work as an account (started by the helper)
//	hostzit-helper ops              list the operations
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/logfile"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	socket := flag.String("socket", helper.SocketPath, "socket path")
	panelUser := flag.String("panel-user", "hostzit", "the user the panel runs as (may use the socket)")
	pdnsURL := flag.String("pdns-url", "http://127.0.0.1:8081/api/v1/servers/localhost", "PowerDNS API")
	pdnsKey := flag.String("pdns-key", "/etc/hostzit/pdns-api.key", "file with the PowerDNS API key")
	flag.Parse()
	args := flag.Args()
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	if cmd == "files-worker" {
		// Runs as the account inside its cage: no logging, no privileges.
		home, err := os.UserHomeDir()
		if err != nil || home == "" || home == "/" {
			home = os.Getenv("HOME")
		}
		return helper.RunWorker(home, os.Stdin, os.Stdout)
	}
	if cmd == "sendmail" {
		// PHP's mail() inside a cage, as the account: into the spool
		return helper.RunSendmail("/.spool", args[1:], os.Stdin)
	}
	if cmd == "version" {
		fmt.Println("hostzit-helper", version)
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("the helper must run as root")
	}
	out := io.Writer(os.Stderr)
	if lw, err := logfile.Open("/var/log/hostzit/helper.log", 0o640); err == nil {
		defer lw.Close()
		out = io.MultiWriter(os.Stderr, lw)
	}
	log := slog.New(slog.NewTextHandler(out, nil))
	h := helper.New(&helper.OS{})
	h.Log = func(format string, a ...any) { log.Info(fmt.Sprintf(format, a...)) }
	h.PDNS = helper.PDNS{URL: *pdnsURL, KeyFile: *pdnsKey}
	if exe, err := os.Executable(); err == nil {
		h.HelperBin = exe
	}
	if g, err := user.LookupGroup(h.WebGroup); err == nil {
		h.WebGID, _ = strconv.Atoi(g.Gid)
	}
	var panelGID = -1
	if u, err := user.Lookup(*panelUser); err == nil {
		h.PanelUID, _ = strconv.Atoi(u.Uid)
		panelGID, _ = strconv.Atoi(u.Gid)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "ops":
		for _, o := range h.Ops() {
			fmt.Println(o)
		}
		return nil
	case "setup":
		return callAndPrint(ctx, h, "system.setup", "{}")
	case "call":
		if len(args) < 2 {
			return errors.New("usage: hostzit-helper call OP [JSON]")
		}
		j := "{}"
		if len(args) > 2 {
			j = args[2]
		}
		return callAndPrint(ctx, h, args[1], j)
	case "cage-mount", "cage-umount":
		if len(args) != 2 {
			return errors.New("usage: hostzit-helper " + cmd + " ACCOUNT")
		}
		if cmd == "cage-mount" {
			return h.CageMount(ctx, args[1])
		}
		return h.CageUnmount(ctx, args[1])
	case "serve":
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}

	_ = os.MkdirAll("/run/hostzit", 0o750)
	if panelGID >= 0 {
		_ = os.Chown("/run/hostzit", 0, panelGID)
	}
	_ = os.Remove(*socket)
	l, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	if panelGID >= 0 {
		_ = os.Chown(*socket, 0, panelGID)
	}
	if err := os.Chmod(*socket, 0o660); err != nil { // #nosec G302 -- the socket: root and the panel group
		return err
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	go h.RunMailer(ctx)
	log.Info("HostZit helper started", "version", version, "socket", *socket, "panel_uid", h.PanelUID, "ops", len(h.Ops()))
	return h.Serve(ctx, l)
}

func callAndPrint(ctx context.Context, h *helper.Helper, op, args string) error {
	resp := h.Do(ctx, helper.Request{Op: op, By: "cli", Args: json.RawMessage(args)})
	if !resp.OK {
		return errors.New(resp.Error)
	}
	if len(resp.Result) > 0 && string(resp.Result) != "null" {
		var v any
		_ = json.Unmarshal(resp.Result, &v)
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
	}
	return nil
}
