// Package backup writes and restores backups of a HostZit server: the
// database and the files of the data directory a new server needs to take
// over (the secret key of the stored passwords, the agent and console
// certificate with its key).
//
// A backup is a gzip-compressed tar file with manifest.json first, then
// database.hzdb (see store.Dump), then the files under files/. With a
// passphrase the whole file is encrypted (see crypt.go).
package backup

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Manifest describes a backup.
type Manifest struct {
	Format        int       `json:"format"`
	Product       string    `json:"product"`
	ServerVersion string    `json:"server_version"`
	Created       time.Time `json:"created"`
	Files         []string  `json:"files"`
}

const (
	manifestName = "manifest.json"
	databaseName = "database.hzdb"
	filesPrefix  = "files/"
	// Ext is the file name ending of backups (.pzb.enc when encrypted).
	Ext = ".pzb"
)

// DataFiles are the parts of the data directory a backup holds.
var DataFiles = []string{"secret.key", "tls", "acme-account.key"}

// Dumper writes the database (store.Store).
type Dumper interface {
	Dump(ctx context.Context, w io.Writer) error
}

// Create writes a backup to w. The database is dumped to a temporary file
// in tmpDir first (tar needs the size).
func Create(ctx context.Context, db Dumper, dataDir, tmpDir, serverVersion, passphrase string, w io.Writer) (*Manifest, error) {
	tmp, err := os.CreateTemp(tmpDir, "db-*.tmp")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	bw := bufio.NewWriterSize(tmp, 1<<20)
	if err := db.Dump(ctx, bw); err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	files, err := dataFiles(dataDir)
	if err != nil {
		return nil, err
	}
	m := &Manifest{Format: 1, Product: "HostZit", ServerVersion: serverVersion, Created: time.Now().UTC(), Files: files}

	out := w
	var enc io.WriteCloser
	if passphrase != "" {
		if enc, err = newEncWriter(w, passphrase); err != nil {
			return nil, err
		}
		out = enc
	}
	gz, _ := gzip.NewWriterLevel(out, gzip.BestSpeed)
	tw := tar.NewWriter(gz)
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := addBytes(tw, manifestName, raw, m.Created); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := addFile(tw, databaseName, tmp); err != nil {
		return nil, err
	}
	for _, rel := range files {
		f, err := os.Open(filepath.Join(dataDir, filepath.FromSlash(rel))) // #nosec G304 -- files of our own data directory
		if err != nil {
			return nil, err
		}
		err = addFile(tw, filesPrefix+rel, f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if enc != nil {
		if err := enc.Close(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// dataFiles lists the regular files of DataFiles (slash paths relative to
// the data directory).
func dataFiles(dataDir string) ([]string, error) {
	var out []string
	for _, top := range DataFiles {
		root := filepath.Join(dataDir, top)
		if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil // directories are implied; links are not followed
			}
			rel, err := filepath.Rel(dataDir, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func addBytes(tw *tar.Writer, name string, b []byte, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: mod, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func addFile(tw *tar.Writer, name string, f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// open returns the tar reader of a backup, decrypting it when needed.
func open(r io.Reader, passphrase string) (*tar.Reader, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(len(encMagic))
	var in io.Reader = br
	if string(head) == encMagic {
		if passphrase == "" {
			return nil, errors.New("this backup is encrypted; give its passphrase")
		}
		_, _ = br.Discard(len(encMagic))
		dr, err := newDecReader(br, passphrase)
		if err != nil {
			return nil, err
		}
		in = dr
	}
	gz, err := gzip.NewReader(in)
	if err != nil {
		if errors.Is(err, ErrPassphrase) {
			return nil, err
		}
		return nil, errors.New("not a HostZit backup")
	}
	return tar.NewReader(gz), nil
}

// readManifest reads the first entry.
func readManifest(tr *tar.Reader) (*Manifest, error) {
	h, err := tr.Next()
	if err != nil || h.Name != manifestName || h.Size > 1<<20 {
		if errors.Is(err, ErrPassphrase) {
			return nil, err
		}
		return nil, errors.New("not a HostZit backup")
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&m); err != nil || m.Product != "HostZit" {
		return nil, errors.New("not a HostZit backup")
	}
	if m.Format != 1 {
		return nil, fmt.Errorf("backup format %d is not known to this version", m.Format)
	}
	return &m, nil
}

// Inspect reads the manifest of a backup (and checks the passphrase).
func Inspect(r io.Reader, passphrase string) (*Manifest, error) {
	tr, err := open(r, passphrase)
	if err != nil {
		return nil, err
	}
	return readManifest(tr)
}

// RestoreDB restores a database dump (store.RestoreDump).
type RestoreDB func(ctx context.Context, r io.Reader) error

// Restore puts a backup back: the database first (one transaction), then
// the files into dataDir. The server must not run meanwhile.
func Restore(ctx context.Context, r io.Reader, passphrase, dataDir string, restoreDB RestoreDB) (*Manifest, error) {
	tr, err := open(r, passphrase)
	if err != nil {
		return nil, err
	}
	m, err := readManifest(tr)
	if err != nil {
		return nil, err
	}
	h, err := tr.Next()
	if err != nil || h.Name != databaseName {
		return nil, errors.New("the backup has no database")
	}
	if err := restoreDB(ctx, tr); err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return m, nil
		}
		if err != nil {
			return nil, err
		}
		if strings.Contains(h.Name, "..") {
			return nil, fmt.Errorf("the backup holds an unexpected entry %q", h.Name)
		}
		rel, ok := strings.CutPrefix(h.Name, filesPrefix)
		if !ok || h.Typeflag != tar.TypeReg || !safeRel(rel) {
			return nil, fmt.Errorf("the backup holds an unexpected entry %q", h.Name)
		}
		dst := filepath.Join(dataDir, filepath.FromSlash(rel))
		if inside, err := filepath.Rel(dataDir, dst); err != nil || strings.HasPrefix(inside, "..") {
			return nil, fmt.Errorf("the backup holds an unexpected entry %q", h.Name)
		}
		if err := writeFile(dst, tr); err != nil {
			return nil, err
		}
	}
}

// safeRel accepts a clean relative slash path inside one of DataFiles.
func safeRel(rel string) bool {
	if rel == "" || path.Clean(rel) != rel || path.IsAbs(rel) || strings.HasPrefix(rel, "../") || rel == ".." || strings.Contains(rel, "\\") {
		return false
	}
	top, _, _ := strings.Cut(rel, "/")
	for _, d := range DataFiles {
		if top == d {
			return true
		}
	}
	return false
}

func writeFile(dst string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".restore"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- checked by safeRel
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil { // #nosec G110 -- our own backup; sizes come from its tar headers
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
