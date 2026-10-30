package helper

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A large archive goes up in 64 MiB parts and is put together at the end.
func TestS3Multipart(t *testing.T) {
	var mu sync.Mutex
	var parts []int64
	var completed string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AK/") {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		q := r.URL.Query()
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && q.Has("uploads"):
			io.WriteString(w, "<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>")
		case r.Method == http.MethodPut && q.Get("uploadId") == "u1":
			n, _ := io.Copy(io.Discard, r.Body)
			parts = append(parts, n)
			w.Header().Set("ETag", `"e`+q.Get("partNumber")+`"`)
		case r.Method == http.MethodPost && q.Get("uploadId") == "u1":
			b, _ := io.ReadAll(r.Body)
			completed = string(b)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	st, _, err := RemoteDest{Type: "s3", Endpoint: srv.URL, Bucket: "b", AccessKey: "AK", SecretKey: "SK"}.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	size := int64(s3PartSize + 1000)
	if err := st.Put(context.Background(), "x/a.tar.gz", bytes.NewReader(make([]byte, size)), size); err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || parts[0] != s3PartSize || parts[1] != 1000 || !strings.Contains(completed, "<PartNumber>2</PartNumber><ETag>\"e2\"</ETag>") {
		t.Fatalf("parts %v completed %s", parts, completed)
	}
}
