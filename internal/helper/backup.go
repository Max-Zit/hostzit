package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/auth"
	"github.com/max-zit/hostzit/internal/hosting"
)

// Account backups and imports. Whatever comes from outside (an archive,
// SQL dumps) is unpacked and loaded as the account, inside its cage; root
// only copies the archive into the account's private /tmp and dumps
// databases into files it creates itself.

// ImportDir holds archives the administrator copied to the server
// (cPanel cpmove-*.tar.gz, HostZit backups).
const ImportDir = "/var/lib/hostzit/import"

// rootCreate makes a new file in an account's private tmp without
// following links, owned by the account.
func rootCreate(path string, uid int) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollowFile, 0o600) // #nosec G304 -- random name in the account's tmp
	if err != nil {
		return nil, err
	}
	if err := f.Chown(uid, uid); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return f, nil
}

func randomName(prefix, ext string) string {
	return prefix + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strings.ToLower(auth.RandomToken(6)) + ext
}

// ImportFile is an archive waiting in ImportDir.
type ImportFile struct {
	Name string    `json:"name"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

func (h *Helper) importList(_ context.Context, _ struct{}) (any, error) {
	if err := h.Sys.Mkdir(ImportDir, 0o700, 0, 0); err != nil {
		return nil, err
	}
	ents, _ := h.Sys.ReadDir(ImportDir)
	out := []ImportFile{}
	for _, e := range ents {
		if e.IsDir() || !importNameRE.MatchString(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err == nil {
			out = append(out, ImportFile{Name: e.Name(), Size: fi.Size(), Time: fi.ModTime().UTC()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out, nil
}

var importNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}\.(tar\.gz|tgz|tar)$`)

type stageArgs struct {
	Account string `json:"account"`
	File    string `json:"file"` // a name in ImportDir
}

// importStage copies an archive into the account's tmp and unpacks it as
// the account into ~/.hz-import.
func (h *Helper) importStage(ctx context.Context, a stageArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if !importNameRE.MatchString(a.File) {
		return nil, userErr("invalid archive name")
	}
	uid, ok := h.lookupID(ctx, "passwd", a.Account)
	if !ok {
		return nil, userErr("no such account")
	}
	src, err := os.OpenFile(filepath.Join(ImportDir, a.File), os.O_RDONLY|noFollowFile, 0) // #nosec G304 -- checked name in the root-only import folder
	if err != nil {
		return nil, userErr("archive not found")
	}
	defer src.Close()
	name := randomName("import-", ".tar.gz")
	dst, err := rootCreate(filepath.Join(hosting.TmpDir(a.Account), name), uid)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return nil, err
	}
	if err := dst.Close(); err != nil {
		return nil, err
	}
	home := hosting.HomeDir(a.Account)
	defer func() { _, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/rm", "-f", "/tmp/"+name) }()
	_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/rm", "-rf", home+"/.hz-import")
	if out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/mkdir", "-p", home+"/.hz-import"); err != nil {
		return nil, userErr(tail(string(out), 200))
	}
	if out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/tar", "-xzf", "/tmp/"+name, "-C", home+"/.hz-import", "--no-same-owner", "--no-same-permissions", "--warning=no-unknown-keyword"); err != nil {
		return nil, userErr("the archive could not be unpacked: " + tail(string(out)+" "+err.Error(), 300))
	}
	return nil, nil
}

type dbImportArgs struct {
	Account string `json:"account"`
	DB      string `json:"db"`
	File    string `json:"file"` // SQL file relative to the home
}

// dbImport loads an SQL file into a database of the account with a
// temporary database user that can reach only that database; the client
// runs as the account in its cage.
func (h *Helper) dbImport(ctx context.Context, a dbImportArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if !hosting.ValidDatabase(a.Account, a.DB) {
		return nil, userErr("invalid database")
	}
	rel, err := hosting.CleanRelPath(a.File)
	if err != nil || rel == "" || !strings.HasSuffix(rel, ".sql") {
		return nil, userErr("invalid SQL file")
	}
	user := a.Account + "_hzimp"
	pw := auth.RandomToken(24)
	if _, err := h.dbUser(ctx, dbUserArgs{Account: a.Account, User: user, Password: pw, Databases: []string{a.DB}, MaxConn: 5}); err != nil {
		return nil, err
	}
	defer func() { _, _ = h.dbUserDrop(ctx, dbUserRef{Account: a.Account, User: user}) }()
	cnf := "[client]\nuser=" + user + "\npassword=" + pw + "\nsocket=/run/mysqld/mysqld.sock\n"
	cnfName := randomName(".hzimp-", ".cnf")
	if _, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "write", Path: cnfName, Data: []byte(cnf)}}); err != nil {
		return nil, err
	}
	home := hosting.HomeDir(a.Account)
	defer func() { _, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/rm", "-f", home+"/"+cnfName) }()
	_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/chmod", "600", home+"/"+cnfName)
	out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/mariadb", "--defaults-extra-file="+home+"/"+cnfName, a.DB, "-e", "source "+home+"/"+rel)
	if err != nil {
		return nil, userErr("import failed: " + tail(string(out)+" "+err.Error(), 400))
	}
	return nil, nil
}

type backupArgs struct {
	Account  string   `json:"account"`
	Name     string   `json:"name"`
	DBs      []string `json:"dbs"`
	Manifest string   `json:"manifest"` // JSON written into the archive
	// toTmp makes the archive in the account's private tmp (for the remote
	// backups) instead of ~/backups.
	toTmp bool
}

// backupCreate makes ~/backups/<name>.tar.gz: the home (without backups),
// the database dumps and the manifest.
func (h *Helper) backupCreate(ctx context.Context, a backupArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if !snapNameRE.MatchString(a.Name) {
		return nil, userErr("invalid backup name")
	}
	if len(a.Manifest) > 1<<20 {
		return nil, userErr("manifest too large")
	}
	uid, ok := h.lookupID(ctx, "passwd", a.Account)
	if !ok {
		return nil, userErr("no such account")
	}
	tmp := hosting.TmpDir(a.Account)
	var made []string
	defer func() {
		for _, f := range made {
			_ = os.Remove(filepath.Join(tmp, f))
		}
	}()
	archive := hosting.HomeDir(a.Account) + "/backups/" + a.Name + ".tar.gz"
	if a.toTmp {
		archive = "/tmp/" + a.Name + ".tar.gz"
	}
	tarArgs := []string{"/usr/bin/tar", "-czf", archive, "--exclude=./backups", "--exclude=./.hz-import", "--exclude=./.hz-keep", "--exclude=./.wp-cli/cache",
		"-C", hosting.HomeDir(a.Account), "."}
	var extra []string
	for _, db := range a.DBs {
		if !hosting.ValidDatabase(a.Account, db) {
			return nil, userErr("invalid database " + db)
		}
		name := randomName("dump-", ".sql")
		f, err := rootCreate(filepath.Join(tmp, name), uid)
		if err != nil {
			return nil, err
		}
		made = append(made, name)
		out, err := h.dumpTo(ctx, db, f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("dump of %s: %v %s", db, err, tail(out, 200))
		}
		// inside the archive the dump is called mysql/<db>.sql
		link := "mysql-" + db + ".sql"
		_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/mv", "/tmp/"+name, "/tmp/"+link)
		made = append(made, link)
		extra = append(extra, link)
	}
	mname := randomName("manifest-", ".json")
	mf, err := rootCreate(filepath.Join(tmp, mname), uid)
	if err != nil {
		return nil, err
	}
	_, _ = mf.WriteString(a.Manifest)
	_ = mf.Close()
	made = append(made, mname)
	_, _ = h.inCage(ctx, a.Account, nil, "/usr/bin/mv", "/tmp/"+mname, "/tmp/hostzit-manifest.json")
	made = append(made, "hostzit-manifest.json")
	extra = append(extra, "hostzit-manifest.json")
	tarArgs = append(tarArgs, "-C", "/tmp")
	tarArgs = append(tarArgs, extra...)
	if out, err := h.inCage(ctx, a.Account, nil, tarArgs...); err != nil {
		return nil, userErr("archive failed: " + tail(string(out)+" "+err.Error(), 300))
	}
	if a.toTmp {
		return map[string]any{"file": filepath.Join(tmp, a.Name+".tar.gz")}, nil
	}
	st, err := h.files(ctx, filesArgs{Account: a.Account, Req: WorkerReq{Op: "stat", Path: "backups/" + a.Name + ".tar.gz"}})
	var size int64
	if r, ok := st.(WorkerResp); err == nil && ok && r.File != nil {
		size = r.File.Size
	}
	return map[string]any{"file": "backups/" + a.Name + ".tar.gz", "size": size}, nil
}

// dumpTo writes a consistent dump of a database into f (as root).
func (h *Helper) dumpTo(ctx context.Context, db string, f *os.File) (string, error) {
	if h.Sys == nil {
		return "", errors.New("no system")
	}
	if o, ok := h.Sys.(*OS); ok && o.Runner == nil && o.Root == "" {
		return runToFile(ctx, f, "mariadb-dump", "--single-transaction", "--quick", "--routines", "--triggers", "--no-tablespaces", db)
	}
	out, err := h.Sys.Run(ctx, nil, "mariadb-dump", "--single-transaction", "--quick", "--routines", "--triggers", "--no-tablespaces", db)
	if err == nil {
		_, err = f.Write(out)
	}
	return string(out), err
}
