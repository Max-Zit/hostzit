package web

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
)

// gzipStatic serves the text files of the static folder (scripts, styles,
// pictures, the picture index) gzip-compressed to browsers that accept it,
// compressing each file once. The picture index alone is ~0.7 MB raw and
// ~50 KB compressed.
func gzipStatic(files fs.FS, next http.Handler) http.Handler {
	var cache sync.Map // name → []byte (nil: not worth it)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		ext := path.Ext(name)
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") || !compressible[ext] {
			next.ServeHTTP(w, r)
			return
		}
		v, ok := cache.Load(name)
		if !ok {
			v = gzipFile(files, name)
			cache.Store(name, v)
		}
		b, _ := v.([]byte)
		if b == nil {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", mime.TypeByExtension(ext))
		h.Set("Content-Encoding", "gzip")
		h.Add("Vary", "Accept-Encoding")
		_, _ = w.Write(b) // #nosec G705 -- the compressed bytes of an embedded static file, not user input
	})
}

var compressible = map[string]bool{".js": true, ".css": true, ".svg": true, ".json": true, ".html": true, ".txt": true}

func gzipFile(files fs.FS, name string) []byte {
	raw, err := fs.ReadFile(files, name)
	if err != nil || len(raw) < 1024 {
		return nil
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(raw); err != nil {
		return nil
	}
	if err := zw.Close(); err != nil {
		return nil
	}
	return buf.Bytes()
}
