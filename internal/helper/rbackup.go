package helper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// Backups like JetBackup: every account goes each night into one restic
// repository (incremental, deduplicated, compressed, encrypted) on a local
// folder, an SFTP server or an S3 bucket. Each run is a restore point of
// the account (tag acct:<name>): its home, a dump of each database and the
// settings (manifest). Customers and administrators browse a restore point
// and put back files and folders, databases, DNS zones or cron jobs.

const (
	resticPass   = "/var/lib/hostzit/private/restic.pass" // #nosec G101 -- the path of the key file, not a key
	resticKey    = "/var/lib/hostzit/private/backup_ed25519"
	resticHosts  = "/var/lib/hostzit/private/backup_known_hosts"
	backupStage  = "/var/lib/hostzit/backup-stage"
	resticHost   = "hostzit"
	resticSubdir = "restic" // below the destination's folder: older archives stay beside it
)

var snapIDRE = regexp.MustCompile(`^[0-9a-f]{8,64}$`)

// resticArgs builds the command (env, repository, password) for a
// destination; extra are restic's own arguments.
func (h *Helper) resticCmd(d RemoteDest, extra ...string) ([]string, error) {
	env := []string{"RESTIC_PASSWORD_FILE=" + h.realPath(resticPass), "RESTIC_CACHE_DIR=" + h.realPath("/var/cache/hostzit/restic"), "HOME=/root"}
	var repo string
	args := []string{}
	sub := strings.Trim(path.Join(strings.Trim(d.Path, "/"), resticSubdir), "/")
	switch d.Type {
	case "local":
		p := "/" + strings.Trim(d.Path, "/")
		if p == "/" || strings.Contains(p, "..") || strings.HasPrefix(p, "/home") || strings.HasPrefix(p, "/var/lib/hostzit/cages") || strings.HasPrefix(p, "/proc") || strings.HasPrefix(p, "/sys") {
			return nil, userErr("choose another folder for the backups (not / or /home)")
		}
		repo = path.Join(p, resticSubdir)
	case "sftp":
		if d.Host == "" || d.User == "" {
			return nil, userErr("enter the SFTP server and user")
		}
		if d.Key == "" {
			return nil, userErr("backups over SFTP need the key of this server (add it on the backup server)")
		}
		port := d.Port
		if port == 0 {
			port = 22
		}
		repo = "sftp:" + d.User + "@" + d.Host + ":" + "/" + sub
		if !strings.HasPrefix(d.Path, "/") {
			repo = "sftp:" + d.User + "@" + d.Host + ":" + sub // relative to the user's home
		}
		args = append(args, "-o", fmt.Sprintf("sftp.command=ssh -i %s -p %d -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s %s@%s -s sftp",
			h.realPath(resticKey), port, h.realPath(resticHosts), d.User, d.Host))
	case "s3":
		if d.Bucket == "" || d.AccessKey == "" || d.SecretKey == "" {
			return nil, userErr("enter the bucket and the access keys")
		}
		ep := strings.TrimRight(d.Endpoint, "/")
		if ep == "" {
			ep = "https://s3.amazonaws.com"
		}
		repo = "s3:" + ep + "/" + d.Bucket + "/" + sub
		env = append(env, "AWS_ACCESS_KEY_ID="+d.AccessKey, "AWS_SECRET_ACCESS_KEY="+d.SecretKey)
		if d.Region != "" {
			env = append(env, "AWS_DEFAULT_REGION="+d.Region)
		}
	default:
		return nil, userErr("choose a destination")
	}
	out := append([]string{}, env...)
	out = append(out, "restic", "--repo", repo)
	out = append(out, args...)
	return append(out, extra...), nil
}

// restic runs restic for a destination and returns its standard output.
// A lock left by a backup or cleanup that was cut off (helper restart,
// power loss) is removed and the command runs once more.
func (h *Helper) restic(ctx context.Context, d RemoteDest, extra ...string) ([]byte, error) {
	argv, err := h.resticCmd(d, extra...)
	if err != nil {
		return nil, err
	}
	out, err := h.Sys.Run(ctx, nil, "env", argv...)
	if err != nil && isLocked(string(out)+err.Error()) {
		h.resticUnlock(ctx, d)
		out, err = h.Sys.Run(ctx, nil, "env", argv...)
		if err != nil && isLocked(string(out)+err.Error()) {
			return out, userErr("the backups are busy (a backup or a cleanup is running); try again in a few minutes")
		}
	}
	return out, err
}

func isLocked(s string) bool { return strings.Contains(s, "already locked") }

// resticUnlock removes stale locks (of processes that no longer run).
func (h *Helper) resticUnlock(ctx context.Context, d RemoteDest) {
	if argv, err := h.resticCmd(d, "unlock"); err == nil {
		_, _ = h.Sys.Run(ctx, nil, "env", argv...)
	}
}

type rbDestArgs struct {
	Dest RemoteDest `json:"dest"`
}

// rbackupInit prepares restic (package, password, SSH key) and creates the
// repository when it does not exist yet.
func (h *Helper) rbackupInit(ctx context.Context, a rbDestArgs) (any, error) {
	if !h.Sys.Exists("/usr/bin/restic") {
		if out, err := h.apt(ctx, "install", "restic"); err != nil {
			return nil, userErr("restic could not be installed: " + tail(string(out), 300))
		}
	}
	_ = h.Sys.Mkdir("/var/lib/hostzit/private", 0o700, 0, 0)
	_ = h.Sys.Mkdir("/var/cache/hostzit/restic", 0o700, 0, 0)
	if !h.Sys.Exists(resticPass) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		if err := h.Sys.WriteFile(resticPass, []byte(base64.RawURLEncoding.EncodeToString(b)+"\n"), 0o600, 0, 0); err != nil {
			return nil, err
		}
	}
	if a.Dest.Type == "sftp" && a.Dest.Key != "" {
		if err := h.Sys.WriteFile(resticKey, []byte(strings.TrimSpace(a.Dest.Key)+"\n"), 0o600, 0, 0); err != nil {
			return nil, err
		}
	}
	if a.Dest.Type == "local" {
		if argv, err := h.resticCmd(a.Dest); err == nil {
			for i, s := range argv {
				if s == "--repo" && i+1 < len(argv) {
					_ = os.MkdirAll(h.realPath(path.Dir(argv[i+1])), 0o700) // #nosec G703 -- checked in resticCmd
				}
			}
		}
	}
	if _, err := h.restic(ctx, a.Dest, "cat", "config"); err == nil {
		h.resticUnlock(ctx, a.Dest) // stale locks of a round that was cut off
		return map[string]string{"repository": "ready"}, nil
	}
	if out, err := h.restic(ctx, a.Dest, "init"); err != nil {
		return nil, userErr("the backup repository could not be created: " + tail(string(out)+" "+err.Error(), 400))
	}
	return map[string]string{"repository": "created"}, nil
}

// rbackupKey shows the repository password (needed to restore on another server).
func (h *Helper) rbackupKey(_ context.Context, _ struct{}) (any, error) {
	b, err := h.Sys.ReadFile(resticPass)
	if err != nil {
		return nil, userErr("no backup key yet")
	}
	return map[string]string{"key": strings.TrimSpace(string(b))}, nil
}

type rbRunArgs struct {
	Dest     RemoteDest `json:"dest"`
	Account  string     `json:"account"`
	DBs      []string   `json:"dbs"`
	Manifest string     `json:"manifest"`
}

// stageDir holds the database dumps and the manifest of an account while
// its backup runs (they are part of the restore point).
func stageDir(account string) string { return backupStage + "/" + account }

// rbackupRun makes a restore point of an account.
func (h *Helper) rbackupRun(ctx context.Context, a rbRunArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if len(a.Manifest) > 4<<20 {
		return nil, userErr("manifest too large")
	}
	stage := stageDir(a.Account)
	_ = h.Sys.Mkdir(backupStage, 0o700, 0, 0)
	_ = h.Sys.RemoveAll(stage)
	if err := h.Sys.Mkdir(stage+"/db", 0o700, 0, 0); err != nil {
		return nil, err
	}
	defer h.Sys.RemoveAll(stage) //nolint:errcheck
	for _, db := range a.DBs {
		if !hosting.ValidDatabase(a.Account, db) {
			return nil, userErr("invalid database " + db)
		}
		f, err := os.OpenFile(h.realPath(stage+"/db/"+db+".sql"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- validated name below the stage
		if err != nil {
			return nil, err
		}
		out, err := h.dumpTo(ctx, db, f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("dump of %s: %v %s", db, err, tail(out, 200))
		}
	}
	if err := h.Sys.WriteFile(stage+"/manifest.json", []byte(a.Manifest), 0o600, 0, 0); err != nil {
		return nil, err
	}
	home := hosting.HomeDir(a.Account)
	args := []string{"backup", "--json", "--host", resticHost, "--tag", "hz", "--tag", "acct:" + a.Account}
	for _, ex := range []string{"backups", ".hz-import", ".hz-keep", ".wp-cli/cache", ".cache", ".quarantine"} {
		args = append(args, "--exclude", home+"/"+ex)
	}
	args = append(args, home, stage)
	argv, err := h.resticCmd(a.Dest, args...)
	if err != nil {
		return nil, err
	}
	// the lowest priority: websites stay fast while the backup runs
	out, err := h.Sys.Run(ctx, nil, "nice", append([]string{"-n", "19", "ionice", "-c", "3", "env"}, argv...)...)
	if err != nil && isLocked(string(out)+err.Error()) {
		h.resticUnlock(ctx, a.Dest)
		out, err = h.Sys.Run(ctx, nil, "nice", append([]string{"-n", "19", "ionice", "-c", "3", "env"}, argv...)...)
	}
	if err != nil {
		return nil, userErr("backup failed: " + tail(string(out)+" "+err.Error(), 400))
	}
	var sum struct {
		MessageType string  `json:"message_type"`
		SnapshotID  string  `json:"snapshot_id"`
		DataAdded   int64   `json:"data_added"`
		TotalBytes  int64   `json:"total_bytes_processed"`
		Duration    float64 `json:"total_duration"`
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil && m["message_type"] == "summary" {
			_ = json.Unmarshal(sc.Bytes(), &sum)
		}
	}
	return map[string]any{"snapshot": sum.SnapshotID, "added": sum.DataAdded, "total": sum.TotalBytes, "seconds": sum.Duration}, nil
}

type rbForgetArgs struct {
	Dest    RemoteDest `json:"dest"`
	Daily   int        `json:"daily"`
	Weekly  int        `json:"weekly"`
	Monthly int        `json:"monthly"`
	Account string     `json:"account,omitempty"` // "" = every account
}

// rbackupForget removes restore points beyond the retention and frees their space.
func (h *Helper) rbackupForget(ctx context.Context, a rbForgetArgs) (any, error) {
	if a.Daily < 1 || a.Daily > 365 || a.Weekly < 0 || a.Weekly > 104 || a.Monthly < 0 || a.Monthly > 120 {
		return nil, userErr("invalid retention")
	}
	args := []string{"forget", "--tag", "hz", "--group-by", "host,tags", "--keep-daily", strconv.Itoa(a.Daily), "--keep-weekly", strconv.Itoa(a.Weekly),
		"--keep-monthly", strconv.Itoa(a.Monthly), "--prune"}
	if a.Account != "" {
		if err := hosting.ValidAccount(a.Account); err != nil {
			return nil, userErr(err.Error())
		}
		args = append(args, "--tag", "acct:"+a.Account)
	}
	if out, err := h.restic(ctx, a.Dest, args...); err != nil {
		return nil, userErr("cleaning up old restore points failed: " + tail(string(out)+" "+err.Error(), 400))
	}
	return nil, nil
}

// RestorePoint is a backup run of an account.
type RestorePoint struct {
	ID    string    `json:"id"`
	Time  time.Time `json:"time"`
	Bytes int64     `json:"bytes"`
}

type rbAccountArgs struct {
	Dest    RemoteDest `json:"dest"`
	Account string     `json:"account"`
}

func (h *Helper) rbPoints(ctx context.Context, d RemoteDest, account string) ([]RestorePoint, error) {
	if err := hosting.ValidAccount(account); err != nil {
		return nil, userErr(err.Error())
	}
	out, err := h.restic(ctx, d, "snapshots", "--json", "--host", resticHost, "--tag", "acct:"+account)
	if err != nil {
		return nil, userErr("the restore points could not be read: " + tail(string(out)+" "+err.Error(), 300))
	}
	var snaps []struct {
		ShortID string    `json:"short_id"`
		ID      string    `json:"id"`
		Time    time.Time `json:"time"`
		Summary struct {
			TotalBytes int64 `json:"total_bytes_processed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("restic snapshots: %w", err)
	}
	res := make([]RestorePoint, 0, len(snaps))
	for _, s := range snaps {
		res = append(res, RestorePoint{ID: s.ID, Time: s.Time, Bytes: s.Summary.TotalBytes})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Time.After(res[j].Time) })
	return res, nil
}

func (h *Helper) rbackupPoints(ctx context.Context, a rbAccountArgs) (any, error) {
	return h.rbPoints(ctx, a.Dest, a.Account)
}

type rbPointArgs struct {
	Dest     RemoteDest `json:"dest"`
	Account  string     `json:"account"`
	Snapshot string     `json:"snapshot"`
	Path     string     `json:"path,omitempty"` // below the home ("" = the home)
}

// check makes sure the restore point belongs to the account.
func (h *Helper) rbCheck(ctx context.Context, a rbPointArgs) error {
	if !snapIDRE.MatchString(a.Snapshot) {
		return userErr("invalid restore point")
	}
	pts, err := h.rbPoints(ctx, a.Dest, a.Account)
	if err != nil {
		return err
	}
	for _, p := range pts {
		if p.ID == a.Snapshot {
			return nil
		}
	}
	return userErr("no such restore point")
}

// cleanRel turns a path below the home into a clean relative one.
func cleanRel(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	c := path.Clean(p)
	if c == "." || strings.HasPrefix(c, "..") || strings.Contains(p, "\x00") {
		return "", userErr("invalid path")
	}
	return c, nil
}

// RestoreEntry is a file or folder in a restore point.
type RestoreEntry struct {
	Name  string    `json:"name"`
	Dir   bool      `json:"dir"`
	Size  int64     `json:"size"`
	MTime time.Time `json:"mtime"`
}

// rbackupLs lists a folder of the account's home in a restore point.
func (h *Helper) rbackupLs(ctx context.Context, a rbPointArgs) (any, error) {
	if err := h.rbCheck(ctx, a); err != nil {
		return nil, err
	}
	rel, err := cleanRel(a.Path)
	if err != nil {
		return nil, err
	}
	dir := hosting.HomeDir(a.Account)
	if rel != "" {
		dir += "/" + rel
	}
	out, err := h.restic(ctx, a.Dest, "ls", "--json", a.Snapshot, dir)
	if err != nil {
		return nil, userErr("the restore point could not be read: " + tail(string(out)+" "+err.Error(), 300))
	}
	res := []RestoreEntry{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var n struct {
			Path  string    `json:"path"`
			Name  string    `json:"name"`
			Type  string    `json:"type"`
			Size  int64     `json:"size"`
			MTime time.Time `json:"mtime"`
		}
		if json.Unmarshal(sc.Bytes(), &n) != nil || n.Path == "" || path.Dir(n.Path) != dir {
			continue
		}
		res = append(res, RestoreEntry{Name: n.Name, Dir: n.Type == "dir", Size: n.Size, MTime: n.MTime})
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Dir != res[j].Dir {
			return res[i].Dir
		}
		return res[i].Name < res[j].Name
	})
	return res, nil
}

// rbackupManifest reads the settings saved with a restore point.
func (h *Helper) rbackupManifest(ctx context.Context, a rbPointArgs) (any, error) {
	if err := h.rbCheck(ctx, a); err != nil {
		return nil, err
	}
	out, err := h.restic(ctx, a.Dest, "dump", a.Snapshot, stageDir(a.Account)+"/manifest.json")
	if err != nil {
		return nil, userErr("the settings of the restore point could not be read: " + tail(string(out)+" "+err.Error(), 300))
	}
	return map[string]string{"manifest": string(out)}, nil
}

type rbRestoreArgs struct {
	rbPointArgs
	// ToFolder puts the files into ~/restored-<date>/… instead of their place.
	ToFolder bool `json:"to_folder"`
}

// rbackupRestoreFiles puts a file or folder of a restore point back, into
// its place or into ~/restored-<date>/. restic (as root) streams it; tar or
// dd write it as the account inside its cage, so nothing outside the home
// can be touched.
func (h *Helper) rbackupRestoreFiles(ctx context.Context, a rbRestoreArgs) (any, error) {
	if err := h.rbCheck(ctx, a.rbPointArgs); err != nil {
		return nil, err
	}
	rel, err := cleanRel(a.Path)
	if err != nil {
		return nil, err
	}
	home := hosting.HomeDir(a.Account)
	src := home
	if rel != "" {
		src += "/" + rel
	}
	// a folder or a file?
	out, err := h.restic(ctx, a.Dest, "ls", "--json", a.Snapshot, src)
	if err != nil {
		return nil, userErr("the restore point could not be read: " + tail(string(out)+" "+err.Error(), 300))
	}
	isDir, found := rel == "", rel == ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var n struct{ Path, Type string }
		if json.Unmarshal(sc.Bytes(), &n) == nil && n.Path == src {
			isDir, found = n.Type == "dir", true
		}
	}
	if !found {
		return nil, userErr("not in this restore point: " + rel)
	}
	base := home // where the restored path lands
	if a.ToFolder {
		base = home + "/restored-" + time.Now().Format("20060102-1504")
	}
	dst := base
	if rel != "" {
		dst += "/" + rel
	}
	mkdir := path.Dir(dst)
	if isDir {
		mkdir = base
	}
	if out, err := h.inCage(ctx, a.Account, nil, "/usr/bin/mkdir", "-p", mkdir); err != nil {
		return nil, userErr("restore failed: " + tail(string(out)+" "+err.Error(), 300))
	}
	var dumpArgv, writer []string
	if isDir {
		// the tar holds home/<account>/… : strip those two parts
		dumpArgv, err = h.resticCmd(a.Dest, "dump", "--archive", "tar", a.Snapshot, src)
		writer = []string{"/usr/bin/tar", "-x", "--no-same-owner", "--strip-components=2", "-C", base}
	} else {
		dumpArgv, err = h.resticCmd(a.Dest, "dump", a.Snapshot, src)
		writer = []string{"/usr/bin/dd", "of=" + dst, "status=none"}
	}
	if err != nil {
		return nil, err
	}
	cage := append(append([]string{}, h.cageArgs(a.Account)...), "--")
	if out, err := h.pipe(ctx, append([]string{"env"}, dumpArgv...), append(append([]string{"systemd-run"}, cage...), writer...)); err != nil {
		return nil, userErr("restore failed: " + tail(out+" "+err.Error(), 400))
	}
	return map[string]string{"to": strings.TrimPrefix(strings.TrimPrefix(dst, home), "/")}, nil
}

type rbDBArgs struct {
	rbPointArgs
	DB string `json:"db"`
}

// rbackupRestoreDB loads a database dump of a restore point into the database.
func (h *Helper) rbackupRestoreDB(ctx context.Context, a rbDBArgs) (any, error) {
	if !hosting.ValidDatabase(a.Account, a.DB) {
		return nil, userErr("invalid database")
	}
	if err := h.rbCheck(ctx, a.rbPointArgs); err != nil {
		return nil, err
	}
	dumpArgv, err := h.resticCmd(a.Dest, "dump", a.Snapshot, stageDir(a.Account)+"/db/"+a.DB+".sql")
	if err != nil {
		return nil, err
	}
	if out, err := h.pipe(ctx, append([]string{"env"}, dumpArgv...), []string{"mariadb", a.DB}); err != nil {
		return nil, userErr("the database could not be restored: " + tail(out+" "+err.Error(), 400))
	}
	return nil, nil
}

// rbackupDBs lists the database dumps of a restore point.
func (h *Helper) rbackupDBs(ctx context.Context, a rbPointArgs) (any, error) {
	if err := h.rbCheck(ctx, a); err != nil {
		return nil, err
	}
	out, err := h.restic(ctx, a.Dest, "ls", "--json", a.Snapshot, stageDir(a.Account)+"/db")
	if err != nil {
		return []string{}, nil
	}
	res := []string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		var n struct {
			Path, Name, Type string
		}
		if json.Unmarshal(sc.Bytes(), &n) == nil && n.Type == "file" && strings.HasSuffix(n.Name, ".sql") {
			res = append(res, strings.TrimSuffix(n.Name, ".sql"))
		}
	}
	return res, nil
}

// pipe runs src | dst and returns the error output.
func (h *Helper) pipe(ctx context.Context, src, dst []string) (string, error) {
	if o, ok := h.Sys.(*OS); ok && (o.Runner != nil || o.Root != "") {
		// tests: run both through the fake runner, without a real pipe
		out, err := o.Run(ctx, nil, src[0], src[1:]...)
		if err != nil {
			return string(out), err
		}
		out, err = o.Run(ctx, out, dst[0], dst[1:]...)
		return string(out), err
	}
	c1 := exec.CommandContext(ctx, src[0], src[1:]...) // #nosec G204 -- fixed programs, validated arguments
	c2 := exec.CommandContext(ctx, dst[0], dst[1:]...) // #nosec G204 -- fixed programs, validated arguments
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=/root"}
	c1.Env, c2.Env = env, env
	r, w := io.Pipe()
	var e1, e2 bytes.Buffer
	c1.Stdout, c1.Stderr = w, &e1
	c2.Stdin, c2.Stdout, c2.Stderr = r, &e2, &e2
	if err := c2.Start(); err != nil {
		return "", err
	}
	err1 := c1.Run()
	_ = w.CloseWithError(err1)
	err2 := c2.Wait()
	if err1 != nil {
		return e1.String(), fmt.Errorf("%s: %w", filepath.Base(src[1]), err1)
	}
	if err2 != nil {
		return e2.String(), err2
	}
	return "", nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["rbackup.init"] = op{handle(h.rbackupInit), false}
		h.ops["rbackup.key"] = op{handle(h.rbackupKey), false}
		h.ops["rbackup.run"] = op{handle(h.rbackupRun), false}
		h.ops["rbackup.forget"] = op{handle(h.rbackupForget), false}
		h.ops["rbackup.points"] = op{handle(h.rbackupPoints), false}
		h.ops["rbackup.ls"] = op{handle(h.rbackupLs), false}
		h.ops["rbackup.dbs"] = op{handle(h.rbackupDBs), false}
		h.ops["rbackup.manifest"] = op{handle(h.rbackupManifest), false}
		h.ops["rbackup.restore.files"] = op{handle(h.rbackupRestoreFiles), false}
		h.ops["rbackup.restore.db"] = op{handle(h.rbackupRestoreDB), false}
	})
}
