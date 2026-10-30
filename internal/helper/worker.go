package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/hosting"
)

// The worker does file work inside an account. The helper starts it with
// systemd-run as the account user, with the account's cage as root
// directory and in the account's slice; it reads one WorkerReq from stdin
// and writes one WorkerResp to stdout. Because it runs as the account, a
// symlink or path trick can only ever reach what the account itself can.

// WorkerReq is one file operation (paths relative to the home).
type WorkerReq struct {
	Op    string `json:"op"` // list, stat, read, write, mkdir, delete, rename, chmod, du, ensure-site
	Path  string `json:"path"`
	To    string `json:"to,omitempty"`
	Data  []byte `json:"data,omitempty"`
	Mode  string `json:"mode,omitempty"` // octal, e.g. "644"
	Limit int64  `json:"limit,omitempty"`
	// Index is written as index.html by ensure-site when the folder is new.
	Index string `json:"index,omitempty"`
}

// FileInfo describes a file.
type FileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	Dir     bool      `json:"dir"`
	Link    string    `json:"link,omitempty"`
	ModTime time.Time `json:"mod_time"`
}

// WorkerResp is the answer.
type WorkerResp struct {
	OK    bool       `json:"ok"`
	Error string     `json:"error,omitempty"`
	Files []FileInfo `json:"files,omitempty"`
	File  *FileInfo  `json:"file,omitempty"`
	Data  []byte     `json:"data,omitempty"`
	Bytes int64      `json:"bytes,omitempty"`
	Count int64      `json:"count,omitempty"`
}

// MaxFileData is the largest file the worker reads or writes in one call.
const MaxFileData = 48 << 20

// RunWorker is the worker's main (hostzit-helper files-worker).
func RunWorker(home string, in io.Reader, out io.Writer) error {
	var req WorkerReq
	if err := json.NewDecoder(io.LimitReader(in, MaxRequest)).Decode(&req); err != nil {
		return json.NewEncoder(out).Encode(WorkerResp{Error: "invalid request"})
	}
	resp, err := workerDo(home, req)
	if err != nil {
		resp = WorkerResp{Error: err.Error()}
	} else {
		resp.OK = true
	}
	return json.NewEncoder(out).Encode(resp)
}

func workerPath(home, rel string) (string, error) {
	p, err := hosting.CleanRelPath(rel)
	if err != nil {
		return "", err
	}
	if p == "" {
		return home, nil
	}
	return filepath.Join(home, filepath.FromSlash(p)), nil
}

func infoOf(name string, fi fs.FileInfo, full string) FileInfo {
	f := FileInfo{Name: name, Size: fi.Size(), Mode: fmt.Sprintf("%o", fi.Mode().Perm()), Dir: fi.IsDir(), ModTime: fi.ModTime().UTC()}
	if fi.Mode()&os.ModeSymlink != 0 {
		f.Link, _ = os.Readlink(full)
	}
	return f
}

func workerDo(home string, r WorkerReq) (WorkerResp, error) {
	p, err := workerPath(home, r.Path)
	if err != nil {
		return WorkerResp{}, err
	}
	switch r.Op {
	case "list":
		ents, err := os.ReadDir(p)
		if err != nil {
			return WorkerResp{}, cleanErr(err, home)
		}
		out := make([]FileInfo, 0, len(ents))
		for _, e := range ents {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, infoOf(e.Name(), fi, filepath.Join(p, e.Name())))
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Dir != out[j].Dir {
				return out[i].Dir
			}
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		})
		return WorkerResp{Files: out}, nil
	case "stat":
		fi, err := os.Lstat(p)
		if err != nil {
			return WorkerResp{}, cleanErr(err, home)
		}
		f := infoOf(filepath.Base(p), fi, p)
		return WorkerResp{File: &f}, nil
	case "read":
		limit := r.Limit
		if limit <= 0 || limit > MaxFileData {
			limit = MaxFileData
		}
		f, err := os.Open(p) // #nosec G304 -- runs as the account inside its cage
		if err != nil {
			return WorkerResp{}, cleanErr(err, home)
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil || fi.IsDir() {
			return WorkerResp{}, errors.New("not a file")
		}
		if fi.Size() > limit {
			return WorkerResp{}, fmt.Errorf("the file is larger than %d MB; use SFTP", limit>>20)
		}
		b, err := io.ReadAll(io.LimitReader(f, limit))
		return WorkerResp{Data: b, Bytes: int64(len(b))}, err
	case "write":
		if len(r.Data) > MaxFileData {
			return WorkerResp{}, errors.New("the file is too large; use SFTP")
		}
		if p == home {
			return WorkerResp{}, errors.New("choose a file name")
		}
		tmp := filepath.Join(filepath.Dir(p), ".hz-upload-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		if err := os.WriteFile(tmp, r.Data, 0o644); err != nil {
			return WorkerResp{}, cleanErr(err, home)
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			return WorkerResp{}, cleanErr(err, home)
		}
		return WorkerResp{Bytes: int64(len(r.Data))}, nil
	case "mkdir":
		return WorkerResp{}, cleanErr(os.MkdirAll(p, 0o755), home)
	case "delete":
		if p == home {
			return WorkerResp{}, errors.New("the home folder cannot be deleted")
		}
		return WorkerResp{}, cleanErr(os.RemoveAll(p), home)
	case "rename":
		to, err := workerPath(home, r.To)
		if err != nil {
			return WorkerResp{}, err
		}
		if p == home || to == home {
			return WorkerResp{}, errors.New("the home folder cannot be moved")
		}
		return WorkerResp{}, cleanErr(os.Rename(p, to), home)
	case "chmod":
		m, err := strconv.ParseUint(r.Mode, 8, 32)
		if err != nil || m > 0o777 {
			return WorkerResp{}, errors.New("the permissions must be octal, e.g. 644")
		}
		return WorkerResp{}, cleanErr(os.Chmod(p, os.FileMode(m)), home)
	case "du":
		var n, c int64
		err := filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if fi, err := d.Info(); err == nil && !d.IsDir() {
				n += fi.Size()
			}
			c++
			return nil
		})
		return WorkerResp{Bytes: n, Count: c}, err
	case "ensure-site":
		// The site folder and its document root; a first page when new.
		if _, err := os.Stat(p); err == nil {
			return WorkerResp{}, nil
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			return WorkerResp{}, cleanErr(err, home)
		}
		if r.Index != "" {
			if err := os.WriteFile(filepath.Join(p, "index.html"), []byte(r.Index), 0o644); err != nil {
				return WorkerResp{}, cleanErr(err, home)
			}
		}
		return WorkerResp{Count: 1}, nil
	}
	return WorkerResp{}, errors.New("unknown file operation")
}

// cleanErr hides the absolute paths in error messages.
func cleanErr(err error, home string) error {
	if err == nil {
		return nil
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		rel := strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(pe.Path), filepath.ToSlash(home)), "/")
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%s: not found", rel)
		case errors.Is(err, fs.ErrPermission):
			return fmt.Errorf("%s: permission denied", rel)
		case errors.Is(err, fs.ErrExist):
			return fmt.Errorf("%s: already exists", rel)
		}
		return fmt.Errorf("%s: %v", rel, pe.Err)
	}
	return err
}

// cageArgs are the systemd-run options that put a command into an
// account's cage and slice, as that account.
func (h *Helper) cageArgs(account string) []string {
	return []string{"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
		"-p", "User=" + account, "-p", "Group=" + account, "-p", "Slice=" + hosting.SliceName(account),
		"-p", "RootDirectory=" + hosting.CageDir(account), "-p", "MountAPIVFS=yes", "-p", "BindPaths=-/run/mysqld", "-p", "ProtectProc=invisible", "-p", "ProcSubset=pid",
		"-p", "PrivateDevices=yes", "-p", "NoNewPrivileges=yes", "-p", "RestrictSUIDSGID=yes", "-p", "CapabilityBoundingSet=",
		"-p", "ProtectKernelTunables=yes", "-p", "ProtectKernelModules=yes", "-p", "ProtectControlGroups=yes", "-p", "LockPersonality=yes",
		"-p", "RestrictNamespaces=yes", "-p", "UMask=0022", "-p", "WorkingDirectory=" + hosting.HomeDir(account),
		"-p", "Environment=HOME=" + hosting.HomeDir(account) + " TMPDIR=/tmp PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8"}
}

// inCage runs a program as the account inside its cage.
func (h *Helper) inCage(ctx context.Context, account string, stdin []byte, argv ...string) ([]byte, error) {
	if err := hosting.ValidAccount(account); err != nil {
		return nil, err
	}
	if !h.Sys.Exists(hosting.CageDir(account) + "/.hz") {
		return nil, userErr("the account's file system view is not ready")
	}
	args := append(h.cageArgs(account), "--")
	return h.Sys.Run(ctx, stdin, "systemd-run", append(args, argv...)...)
}

type filesArgs struct {
	Account string    `json:"account"`
	Req     WorkerReq `json:"req"`
}

// files runs one file operation through the worker.
func (h *Helper) files(ctx context.Context, a filesArgs) (any, error) {
	if err := hosting.ValidAccount(a.Account); err != nil {
		return nil, userErr(err.Error())
	}
	if _, err := hosting.CleanRelPath(a.Req.Path); err != nil {
		return nil, userErr(err.Error())
	}
	in, err := json.Marshal(a.Req)
	if err != nil {
		return nil, err
	}
	out, err := h.inCage(ctx, a.Account, in, h.HelperBin, "files-worker")
	if err != nil {
		return nil, err
	}
	var resp WorkerResp
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("worker answer: %w", err)
	}
	if !resp.OK {
		return nil, userErr(resp.Error)
	}
	return resp, nil
}
