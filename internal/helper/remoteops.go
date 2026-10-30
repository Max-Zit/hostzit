package helper

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

type remoteBackupArgs struct {
	backupArgs
	Dest RemoteDest `json:"dest"`
	Keep int        `json:"keep"`
}

// backupRemote makes an account backup in the account's private tmp,
// uploads it to <path>/<account>/<name>.tar.gz and keeps the newest Keep.
func (h *Helper) backupRemote(ctx context.Context, a remoteBackupArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	uid, ok := h.lookupID(ctx, "passwd", a.Account)
	if !ok {
		return nil, userErr("no such account")
	}
	a.toTmp = true
	res, err := h.backupCreate(ctx, a.backupArgs)
	if err != nil {
		return nil, err
	}
	file, _ := res.(map[string]any)["file"].(string)
	defer os.Remove(file)
	// The archive lies in a folder the account can write: open it without
	// following links and only if the account made it.
	f, err := os.OpenFile(file, os.O_RDONLY|noFollowFile, 0) // #nosec G304 -- the account's private tmp, checked below
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if owner, ok := fileOwner(st); !st.Mode().IsRegular() || !ok || owner != uid {
		return nil, userErr("the archive is not a file of the account")
	}
	store, hostKey, err := a.Dest.open(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	key := a.Dest.key(a.Account, a.Name+".tar.gz")
	if err := store.Put(ctx, key, f, st.Size()); err != nil {
		return nil, userErr("upload failed: " + err.Error())
	}
	pruned := 0
	if a.Keep > 0 {
		objs, err := store.List(ctx, a.Dest.key(a.Account)+"/")
		if err == nil {
			var arch []string
			for _, o := range objs {
				if strings.HasSuffix(o.Key, ".tar.gz") {
					arch = append(arch, o.Key)
				}
			}
			sort.Strings(arch) // names carry the time: oldest first
			for len(arch) > a.Keep {
				if store.Delete(ctx, arch[0]) == nil {
					pruned++
				}
				arch = arch[1:]
			}
		}
	}
	return map[string]any{"key": key, "size": st.Size(), "pruned": pruned, "host_key": hostKey}, nil
}

type remoteDestArgs struct {
	Dest    RemoteDest `json:"dest"`
	Account string     `json:"account,omitempty"`
	Key     string     `json:"key,omitempty"`
}

// backupRemoteTest writes and deletes a small file at the destination.
func (h *Helper) backupRemoteTest(ctx context.Context, a remoteDestArgs) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	store, hostKey, err := a.Dest.open(ctx)
	if err != nil {
		return map[string]string{"host_key": hostKey}, err
	}
	defer store.Close()
	k := a.Dest.key(".hostzit-test")
	err = store.Put(ctx, k, strings.NewReader("HostZit\n"), 8)
	if s3, ok := store.(*s3Store); ok && err != nil && strings.Contains(err.Error(), "NoSuchBucket") {
		// a new bucket (MinIO, a fresh account): make it
		if err = s3.createBucket(ctx); err == nil {
			err = store.Put(ctx, k, strings.NewReader("HostZit\n"), 8)
		}
	}
	if err != nil {
		return nil, userErr("writing failed: " + err.Error())
	}
	_ = store.Delete(ctx, k)
	return map[string]string{"host_key": hostKey}, nil
}

// backupRemoteList lists the archives of an account (or of all accounts).
func (h *Helper) backupRemoteList(ctx context.Context, a remoteDestArgs) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	store, _, err := a.Dest.open(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	if a.Account != "" {
		if err := hosting.ValidAccount(a.Account); err != nil {
			return nil, userErr(err.Error())
		}
		objs, err := store.List(ctx, a.Dest.key(a.Account)+"/")
		return objs, err
	}
	return nil, userErr("choose an account")
}

// backupRemoteFetch downloads an archive into the import folder, where the
// Import page restores it.
func (h *Helper) backupRemoteFetch(ctx context.Context, a remoteDestArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	base := path.Base(a.Key)
	if !strings.HasPrefix(a.Key, a.Dest.key(a.Account)+"/") || !strings.HasSuffix(base, ".tar.gz") || strings.Contains(a.Key, "..") {
		return nil, userErr("not a backup of this account")
	}
	store, _, err := a.Dest.open(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	if err := h.Sys.Mkdir(ImportDir, 0o700, 0, 0); err != nil {
		return nil, err
	}
	name := base
	if !strings.HasPrefix(name, "hostzit-") {
		name = "hostzit-" + name
	}
	tmp := filepath.Join(ImportDir, "."+name+".part")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|noFollowFile, 0o600) // #nosec G304 -- root-only import folder
	if err != nil {
		return nil, err
	}
	if err := store.Get(ctx, a.Key, f); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return nil, userErr("download failed: " + err.Error())
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, filepath.Join(ImportDir, name)); err != nil {
		return nil, err
	}
	return map[string]string{"file": name}, nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["backup.remote"] = op{handle(h.backupRemote), false}
		h.ops["backup.remote.test"] = op{handle(h.backupRemoteTest), false}
		h.ops["backup.remote.list"] = op{handle(h.backupRemoteList), false}
		h.ops["backup.remote.fetch"] = op{handle(h.backupRemoteFetch), false}
	})
}
