// Package testdb runs a private PostgreSQL for tests: one server per test
// binary, one fresh database per test.
package testdb

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
)

var (
	port uint32
	seq  atomic.Int64
)

// Main starts PostgreSQL, runs the tests and stops it. Call it from TestMain.
func Main(m *testing.M) int {
	dir, err := os.MkdirTemp("", "czpg")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	port = uint32(l.Addr().(*net.TCPAddr).Port) // #nosec G115 -- a TCP port fits
	_ = l.Close()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().Port(port).
		RuntimePath(filepath.Join(dir, "rt")).DataPath(filepath.Join(dir, "data")).Logger(io.Discard))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start postgres:", err)
		return 1
	}
	defer pg.Stop()
	return m.Run()
}

// URL creates an empty database for the test and returns its URL.
func URL(t testing.TB) string {
	t.Helper()
	ctx := context.Background()
	admin := fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	c, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	name := fmt.Sprintf("t%d_%d", os.Getpid(), seq.Add(1))
	if _, err := c.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/%s?sslmode=disable", port, name)
}
