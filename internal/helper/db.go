package helper

import (
	"context"
	"crypto/sha1" // #nosec G505 -- MariaDB's mysql_native_password format, not our own hashing
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Customer databases live in MariaDB. Names are checked by
// hosting.DatabaseName (only [a-z0-9_]) and the helper builds the SQL;
// passwords never appear in it — only their mysql_native_password hash,
// which is hex.

func (h *Helper) sql(ctx context.Context, q string) (string, error) {
	out, err := h.Sys.Run(ctx, nil, "mariadb", "--batch", "--skip-column-names", "-e", q)
	return string(out), err
}

// grantName escapes _ (a wildcard in GRANT … ON db.*).
func grantName(db string) string { return strings.ReplaceAll(db, "_", `\_`) }

// NativeHash is MariaDB's mysql_native_password hash of a password.
func NativeHash(pw string) string {
	a := sha1.Sum([]byte(pw)) // #nosec G401 -- the format MariaDB expects
	b := sha1.Sum(a[:])       // #nosec G401
	return "*" + strings.ToUpper(hex.EncodeToString(b[:]))
}

type dbArgs struct {
	Account string `json:"account"`
	Name    string `json:"name"`
}

func (a dbArgs) check() error {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return userErr(err.Error())
	}
	if !hosting.ValidDatabase(a.Account, a.Name) {
		return userErr("invalid database name")
	}
	return nil
}

func (h *Helper) dbCreate(ctx context.Context, a dbArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	_, err := h.sql(ctx, "CREATE DATABASE IF NOT EXISTS `"+a.Name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	return nil, err
}

func (h *Helper) dbDrop(ctx context.Context, a dbArgs) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	_, err := h.sql(ctx, "DROP DATABASE IF EXISTS `"+a.Name+"`")
	return nil, err
}

type dbUserArgs struct {
	Account   string   `json:"account"`
	User      string   `json:"user"`
	Password  string   `json:"password,omitempty"` // empty = keep
	Databases []string `json:"databases"`
	MaxConn   int      `json:"max_conn"`
	// Hash sets a mysql_native_password hash instead of a password
	// (users moved from another server keep their passwords).
	Hash string `json:"hash,omitempty"`
}

// dbUser creates or updates a database user with access to some of the
// account's databases (and nothing else).
func (h *Helper) dbUser(ctx context.Context, a dbUserArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if !hosting.ValidDatabase(a.Account, a.User) || len(a.User) > 80 {
		return nil, userErr("invalid database user name")
	}
	if a.MaxConn < 1 || a.MaxConn > 1000 {
		a.MaxConn = 30
	}
	for _, d := range a.Databases {
		if !hosting.ValidDatabase(a.Account, d) {
			return nil, userErr("invalid database " + d)
		}
	}
	u := "'" + a.User + "'@'localhost'"
	var q strings.Builder
	if a.Hash != "" {
		if !nativeHashRE.MatchString(a.Hash) {
			return nil, userErr("invalid password hash")
		}
		fmt.Fprintf(&q, "CREATE USER IF NOT EXISTS %s IDENTIFIED BY PASSWORD '%s'; ALTER USER %s IDENTIFIED BY PASSWORD '%s'; ", u, a.Hash, u, a.Hash)
	} else if a.Password != "" {
		if len(a.Password) < 10 || len(a.Password) > 200 {
			return nil, userErr("the database password must be 10–200 characters")
		}
		hash := NativeHash(a.Password)
		fmt.Fprintf(&q, "CREATE USER IF NOT EXISTS %s IDENTIFIED BY PASSWORD '%s'; ALTER USER %s IDENTIFIED BY PASSWORD '%s'; ", u, hash, u, hash)
	} else {
		var n string
		out, err := h.sql(ctx, "SELECT count(*) FROM mysql.user WHERE User='"+a.User+"' AND Host='localhost'")
		if err != nil {
			return nil, err
		}
		if n = strings.TrimSpace(out); n == "0" {
			return nil, userErr("a new database user needs a password")
		}
	}
	fmt.Fprintf(&q, "ALTER USER %s WITH MAX_USER_CONNECTIONS %d; REVOKE ALL PRIVILEGES, GRANT OPTION FROM %s; ", u, a.MaxConn, u)
	for _, d := range a.Databases {
		fmt.Fprintf(&q, "GRANT ALL PRIVILEGES ON `%s`.* TO %s; ", grantName(d), u)
	}
	_, err := h.sql(ctx, q.String())
	return nil, err
}

type dbUserRef struct {
	Account string `json:"account"`
	User    string `json:"user"`
}

func (h *Helper) dbUserDrop(ctx context.Context, a dbUserRef) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if !hosting.ValidDatabase(a.Account, a.User) {
		return nil, userErr("invalid database user name")
	}
	_, err := h.sql(ctx, "DROP USER IF EXISTS '"+a.User+"'@'localhost'")
	return nil, err
}

type accountName struct {
	Account string `json:"account"`
}

// dbUsage reports the size of each database of an account in bytes.
func (h *Helper) dbUsage(ctx context.Context, a accountName) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	out, err := h.sql(ctx, "SELECT table_schema, COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema LIKE '"+grantName(a.Account+"_")+"%' GROUP BY table_schema")
	if err != nil {
		return nil, err
	}
	res := map[string]int64{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 2 {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			res[f[0]] = n
		}
	}
	return res, nil
}

var nativeHashRE = regexp.MustCompile(`^\*[0-9A-F]{40}$`)
