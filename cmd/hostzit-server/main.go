// hostzit-server serves the HostZit admin panel, the customer panel and the
// REST API. It runs as the unprivileged hostzit user; every system change
// goes through hostzit-helper.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/helper"
	"github.com/max-zit/hostzit/internal/logfile"
	"github.com/max-zit/hostzit/internal/netacl"
	"github.com/max-zit/hostzit/internal/store"
	"github.com/max-zit/hostzit/internal/tlsutil"
	"github.com/max-zit/hostzit/internal/web"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "HostZit")
		}
	}
	return "/var/lib/hostzit/panel"
}

func run() error {
	dataDir := flag.String("data-dir", env("HOSTZIT_DATA", defaultDataDir()), "data directory (certificates, secret key, logs)")
	dbURL := flag.String("db", os.Getenv("HOSTZIT_DB"), "PostgreSQL URL, e.g. postgres://hostzit:…@localhost/hostzit")
	devDB := flag.Bool("dev-embedded-db", false, "start a private PostgreSQL in the data directory (development only)")
	adminListen := flag.String("admin-listen", "", "admin panel address; overrides the saved setting (e.g. 127.0.0.1:8442)")
	panelListen := flag.String("panel-listen", "", "customer panel address; overrides the saved setting (e.g. :8443)")
	devAdminHTTP := flag.String("dev-http-admin", "", "also serve the admin panel over plain HTTP on this loopback address (development only)")
	devPanelHTTP := flag.String("dev-http-panel", "", "also serve the customer panel over plain HTTP on this loopback address (development only)")
	devNo2FA := flag.Bool("dev-no-2fa", false, "sign in with the password only (development only, needs --dev-embedded-db)")
	devFakeHelper := flag.Bool("dev-fake-helper", false, "run the helper in-process against a fake system in the data directory (development only)")
	helperSocket := flag.String("helper-socket", helper.SocketPath, "socket of hostzit-helper")
	resetACL := flag.Bool("reset-allowlist", false, "allow the admin panel again from the private networks and exit")
	unblock := flag.String("unblock-ip", "", "lift the sign-in block of an address (or \"all\") and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("hostzit-server", version)
		return nil
	}
	if (*devNo2FA || *devFakeHelper) && !*devDB {
		return errors.New("--dev-no-2fa and --dev-fake-helper work only together with --dev-embedded-db")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	var logOut io.Writer = os.Stdout
	if lw, err := logfile.Open(filepath.Join(*dataDir, "logs", "server.log"), 0o600); err == nil {
		defer lw.Close()
		logOut = io.MultiWriter(os.Stdout, lw)
	}
	log := slog.New(slog.NewTextHandler(logOut, nil))

	if *devDB {
		pg, url, err := startEmbeddedDB(*dataDir)
		if err != nil {
			return fmt.Errorf("embedded database: %w", err)
		}
		defer pg.Stop()
		*dbURL = url
		log.Warn("using the embedded development database", "dir", filepath.Join(*dataDir, "pgdata"))
	}
	if *dbURL == "" {
		return errors.New("database URL required (--db or HOSTZIT_DB)")
	}
	st, err := store.Open(ctx, *dbURL)
	if err != nil {
		return err
	}
	defer st.Close()
	key, created, err := store.LoadOrCreateSecretKey(*dataDir)
	if err != nil {
		return fmt.Errorf("secret key: %w", err)
	}
	if err := st.UseSecretKey(key); err != nil {
		return err
	}
	if created {
		log.Warn("created a new secret key; back it up together with the database", "file", filepath.Join(*dataDir, store.SecretKeyFile))
	}
	switch {
	case *resetACL:
		if err := web.ResetMgmtAllowList(ctx, st); err != nil {
			return err
		}
		_ = st.Audit(ctx, "-", "local", "settings.network.reset", "settings", "admin allow-list reset to the private networks from the command line")
		fmt.Println("The admin panel allows the private networks again. Restart the service if it is running.")
		return nil
	case *unblock != "":
		n, err := st.Unblock(ctx, *unblock)
		if err != nil {
			return err
		}
		_ = st.Audit(ctx, "-", "local", "login.unblock", "ip:"+*unblock, "sign-in block lifted from the command line")
		fmt.Printf("Lifted %d block(s).\n", n)
		return nil
	}

	var hc web.Helper = &helper.Client{Path: *helperSocket}
	challenges := ""
	if *devFakeHelper {
		root := filepath.Join(*dataDir, "fakeroot")
		h := helper.New(&helper.OS{Root: root, Runner: fakeRunner(root), Mounter: func(helper.MountReq) error { return nil }})
		h.WebGID = 990
		h.Log = func(format string, a ...any) { log.Info("helper: " + fmt.Sprintf(format, a...)) }
		for _, p := range []string{"usr/sbin/php-fpm8.3", "usr/sbin/php-fpm8.4", "usr/bin/env", "etc/resolv.conf", "etc/hosts"} {
			_ = os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
			_ = os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644)
		}
		hc = inProcess{h}
		challenges = filepath.Join(root, "var", "lib", "zit-acme", "challenges")
		_ = os.MkdirAll(challenges, 0o755)
		log.Warn("TEST MODE: the helper runs in-process against a fake system", "root", root)
	}
	srv, err := web.New(ctx, st, hc, log)
	if err != nil {
		return err
	}
	srv.Version = version
	srv.DataDir = *dataDir
	if challenges != "" {
		srv.ACMEChallengeDir = challenges
	}
	if *devNo2FA {
		srv.DevNo2FA = true
		log.Warn("TEST MODE: two-factor sign-in is switched off (--dev-no-2fa); never use this on a production server")
		_ = st.Audit(ctx, "-", "local", "settings.2fa.off", "server", "server started with --dev-no-2fa: sign-in with the password only")
	}
	net0, err := srv.Network(ctx)
	if err != nil {
		return err
	}
	if *adminListen != "" {
		net0.AdminListen = *adminListen
	}
	if *panelListen != "" {
		net0.PanelListen = *panelListen
	}
	if err := net0.Validate(); err != nil {
		return err
	}
	srv.RunningAdmin, srv.RunningPanel = net0.AdminListen, net0.PanelListen
	srv.ListenOverride = *adminListen != "" || *panelListen != ""
	cert, err := tlsutil.LoadOrCreate(filepath.Join(*dataDir, "tls"), "panel", "HostZit panel", 5)
	if err != nil {
		return fmt.Errorf("panel certificate: %w", err)
	}
	if n, err := st.UserCount(ctx); err != nil {
		return err
	} else if n == 0 {
		tok := auth.RandomToken(18)
		p := filepath.Join(*dataDir, "setup-token.txt")
		if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
			return err
		}
		srv.SetSetupToken(tok)
		srv.SetupTokenFile = p
		log.Warn("no administrators yet: open the admin panel and finish the setup; the setup token is in the file", "file", p)
	}

	errc := make(chan error, 4)
	var servers []*http.Server
	serve := func(name, addr string, h http.Handler, acl *netacl.List) error {
		raw, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s listener %s: %w", name, addr, err)
		}
		l := tls.NewListener(&netacl.Listener{Listener: raw, List: acl, OnRefuse: func(remote string) {
			log.Debug("connection refused by allow-list", "listener", name, "remote", remote)
		}}, tlsutil.ServerConfig(cert))
		hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute,
			IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
		servers = append(servers, hs)
		go func() { errc <- hs.Serve(l) }()
		log.Info("listening", "listener", name, "addr", raw.Addr().String())
		return nil
	}
	if err := serve("admin", net0.AdminListen, srv.AdminHandler(), srv.AdminACL); err != nil {
		return err
	}
	if err := serve("customer", net0.PanelListen, srv.CustomerHandler(), srv.PanelACL); err != nil {
		return err
	}
	for _, d := range []struct {
		addr string
		h    http.Handler
	}{{*devAdminHTTP, srv.AdminHandler()}, {*devPanelHTTP, srv.CustomerHandler()}} {
		if d.addr == "" {
			continue
		}
		a, ok := netacl.AddrOf(d.addr)
		if !ok || !a.IsLoopback() {
			return errors.New("--dev-http-* must be a loopback address such as 127.0.0.1:8080")
		}
		hs := &http.Server{Addr: d.addr, Handler: d.h, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, hs)
		go func() { errc <- hs.ListenAndServe() }()
		log.Warn("development HTTP panel (no TLS)", "addr", d.addr)
	}
	log.Info("HostZit server started", "version", version)
	done := make(chan struct{})
	go func() { srv.Run(ctx); close(done) }()

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	stop()
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, h := range servers {
		_ = h.Shutdown(shut)
	}
	<-done
	srv.Wait()
	log.Info("stopped")
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// inProcess calls a helper in the same process (development).
type inProcess struct{ h *helper.Helper }

func (p inProcess) CallAs(ctx context.Context, by, reqID, op string, args, result any) error {
	c := &helper.Client{Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go p.h.ServeConn(ctx, b)
		return a, nil
	}}
	return c.CallAs(ctx, by, reqID, op, args, result)
}

// fakeRunner pretends that system programs work; the worker runs for real
// inside the fake root, so the file manager can be tried.
func fakeRunner(root string) func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	users := map[string]string{}
	return func(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		switch name {
		case "getent":
			if id, ok := users[args[0]+":"+args[1]]; ok {
				return []byte(args[1] + ":x:" + id + ":" + id + "::/:/bin/sh\n"), nil
			}
			return nil, errors.New("not found")
		case "useradd", "groupadd":
			db := "passwd"
			if name == "groupadd" {
				db = "group"
			}
			id := args[1]
			if name == "groupadd" {
				id = args[len(args)-2]
			}
			users[db+":"+args[len(args)-1]] = id
		case "systemd-run":
			account := ""
			for i, a := range args {
				if strings.HasPrefix(a, "User=") && i > 0 {
					account = strings.TrimPrefix(a, "User=")
				}
			}
			var out bytes.Buffer
			home := filepath.Join(root, "home", account)
			_ = os.MkdirAll(home, 0o755)
			err := helper.RunWorker(home, bytes.NewReader(stdin), &out)
			return out.Bytes(), err
		case "mariadb":
			return []byte("0\n"), nil
		}
		return nil, nil
	}
}

func startEmbeddedDB(dir string) (*embeddedpostgres.EmbeddedPostgres, string, error) {
	const port = 54359
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().Port(port).
		DataPath(filepath.Join(dir, "pgdata")).RuntimePath(filepath.Join(dir, "pgrt")).
		BinariesPath(filepath.Join(dir, "pgbin")).Database("hostzit").Logger(io.Discard))
	if _, err := os.Stat(filepath.Join(dir, "pgdata", "postmaster.pid")); err == nil {
		ctl := filepath.Join(dir, "pgbin", "bin", "pg_ctl")
		if runtime.GOOS == "windows" {
			ctl += ".exe"
		}
		_ = exec.Command(ctl, "stop", "-D", filepath.Join(dir, "pgdata"), "-m", "fast").Run() // #nosec G204 -- our own binary in the data directory
	}
	if err := pg.Start(); err != nil {
		return nil, "", err
	}
	return pg, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/hostzit?sslmode=disable", port), nil
}
