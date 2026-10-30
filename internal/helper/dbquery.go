package helper

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// The database manager of the customer panel (like phpMyAdmin) runs SQL as
// a MariaDB user made for this one request: it may use only the account's
// own databases (ALL on each of them, no global rights such as FILE, no
// GRANT, no new databases) and is dropped afterwards. So even SQL typed by
// the customer cannot reach other accounts' data or the server.

type dbQueryArgs struct {
	Account string `json:"account"`
	// DBs are the account's databases (from the panel); the request may use
	// only these.
	DBs []string `json:"dbs"`
	// DB is the default database of the statements ("" = none).
	DB  string `json:"db"`
	SQL string `json:"sql"`
}

// ResultSet is the answer of one statement.
type ResultSet struct {
	Statement string      `json:"statement"`
	Columns   []string    `json:"columns"`
	Rows      [][]*string `json:"rows"` // nil = NULL
	Truncated bool        `json:"truncated"`
}

const (
	queryRowLimit  = 1000
	queryTimeLimit = 30 // seconds per statement
	queryOutLimit  = 8 << 20
)

func (h *Helper) dbQuery(ctx context.Context, a dbQueryArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if len(a.DBs) == 0 {
		return nil, userErr("the account has no databases")
	}
	for _, d := range a.DBs {
		if !hosting.ValidDatabase(a.Account, d) {
			return nil, userErr("invalid database name")
		}
	}
	if a.DB != "" && !contains(a.DBs, a.DB) {
		return nil, userErr("not a database of this account")
	}
	if strings.TrimSpace(a.SQL) == "" || len(a.SQL) > 1<<20 {
		return nil, userErr("enter SQL (at most 1 MB)")
	}
	user, cnf, cleanup, err := h.tempDBUser(ctx, a.Account, a.DBs)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	args := []string{"--defaults-extra-file=" + cnf, "--xml", "--max-allowed-packet=64M"}
	if a.DB != "" {
		args = append(args, "--database="+a.DB)
	}
	in := fmt.Sprintf("SET SESSION max_statement_time=%d; SET SESSION sql_select_limit=%d;\n%s\n", queryTimeLimit, queryRowLimit+1, a.SQL)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, runErr := h.Sys.Run(ctx, []byte(in), "mariadb", args...)
	if len(out) > queryOutLimit {
		out = out[:queryOutLimit]
	}
	sets, perr := parseResultSets(out)
	res := map[string]any{"sets": sets}
	if runErr != nil {
		msg := runErr.Error()
		if i := strings.Index(msg, "ERROR "); i >= 0 {
			msg = msg[i:]
		}
		res["error"] = strings.ReplaceAll(msg, user, "you")
	} else if perr != nil {
		res["error"] = "the answer could not be read: " + perr.Error()
	}
	return res, nil
}

// tempDBUser makes the one-request MariaDB user and its option file.
func (h *Helper) tempDBUser(ctx context.Context, account string, dbs []string) (user, cnf string, cleanup func(), err error) {
	b := make([]byte, 21)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, err
	}
	user = "hzq_" + account + "_" + hex.EncodeToString(b[:3])
	pw := hex.EncodeToString(b[3:])
	q := "CREATE USER '" + user + "'@'localhost' IDENTIFIED BY PASSWORD '" + NativeHash(pw) + "' WITH MAX_USER_CONNECTIONS 2;"
	for _, d := range dbs {
		q += "GRANT ALL PRIVILEGES ON `" + grantName(d) + "`.* TO '" + user + "'@'localhost';"
	}
	if _, err := h.sql(ctx, q); err != nil {
		_, _ = h.sql(context.Background(), "DROP USER IF EXISTS '"+user+"'@'localhost'")
		return "", "", nil, err
	}
	cnf = "/var/lib/hostzit/private/" + user + ".cnf"
	_ = h.Sys.Mkdir("/var/lib/hostzit/private", 0o700, 0, 0)
	if err := h.Sys.WriteFile(cnf, []byte("[client]\nuser="+user+"\npassword="+pw+"\n"), 0o600, 0, 0); err != nil {
		_, _ = h.sql(context.Background(), "DROP USER IF EXISTS '"+user+"'@'localhost'")
		return "", "", nil, err
	}
	cleanup = func() {
		_ = h.Sys.Remove(cnf)
		_, _ = h.sql(context.Background(), "DROP USER IF EXISTS '"+user+"'@'localhost'")
	}
	return user, cnf, cleanup, nil
}

// parseResultSets reads the --xml output of the MariaDB client.
func parseResultSets(out []byte) ([]ResultSet, error) {
	var sets []ResultSet
	d := xml.NewDecoder(bytes.NewReader(out))
	var cur *ResultSet
	var row []*string
	var cols []string
	for {
		t, err := d.Token()
		if errors.Is(err, io.EOF) {
			return sets, nil
		}
		if err != nil {
			return sets, err
		}
		switch e := t.(type) {
		case xml.StartElement:
			switch e.Name.Local {
			case "resultset":
				sets = append(sets, ResultSet{Statement: attr(e, "statement")})
				cur = &sets[len(sets)-1]
			case "row":
				row, cols = nil, nil
			case "field":
				name := attr(e, "name")
				nilv := attr(e, "nil") == "true"
				var text string
				if err := d.DecodeElement(&text, &e); err != nil {
					return sets, err
				}
				cols = append(cols, name)
				if nilv {
					row = append(row, nil)
				} else {
					v := text
					row = append(row, &v)
				}
			}
		case xml.EndElement:
			if e.Name.Local == "row" && cur != nil {
				if cur.Columns == nil {
					cur.Columns = cols
				}
				if len(cur.Rows) >= queryRowLimit {
					cur.Truncated = true
				} else {
					cur.Rows = append(cur.Rows, row)
				}
			}
		}
	}
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

type dbExportArgs struct {
	Account string `json:"account"`
	Name    string `json:"name"`
}

// dbExport writes a dump of one database into ~/backups of the account
// (gzip), where the customer downloads it with the file manager. Root
// only creates the dump in the account's private tmp; compressing and
// moving it happen as the account in its cage (no root writes in the home).
func (h *Helper) dbExport(ctx context.Context, a dbExportArgs) (any, error) {
	if err := (dbArgs{Account: a.Account, Name: a.Name}).check(); err != nil {
		return nil, err
	}
	uid, ok := h.lookupID(ctx, "passwd", a.Account)
	if !ok {
		return nil, userErr("no such account")
	}
	tmp := hosting.TmpDir(a.Account)
	name := randomName("export-", ".sql")
	f, err := rootCreate(filepath.Join(tmp, name), uid)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.Remove(filepath.Join(tmp, name))
		_ = os.Remove(filepath.Join(tmp, name+".gz"))
	}()
	out, err := h.dumpTo(ctx, a.Name, f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("dump: %v %s", err, tail(out, 200))
	}
	if out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/gzip", "-f", "/tmp/"+name); err != nil {
		return nil, userErr("compressing failed: " + tail(string(out)+" "+err.Error(), 200))
	}
	final := a.Name + "-" + time.Now().UTC().Format("20060102-150405") + ".sql.gz"
	if out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/mv", "/tmp/"+name+".gz", hosting.HomeDir(a.Account)+"/backups/"+final); err != nil {
		return nil, userErr("moving the export failed: " + tail(string(out)+" "+err.Error(), 200))
	}
	return map[string]any{"file": "backups/" + final}, nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["db.query"] = op{handle(h.dbQuery), false}
		h.ops["db.export"] = op{handle(h.dbExport), false}
	})
}
