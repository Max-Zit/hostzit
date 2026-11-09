package helper

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestImportMailSendsTheArchive(t *testing.T) {
	h, _, root, _ := newTest(t)
	var got []byte
	var auth, ctype, path string
	ez := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		auth, ctype, path = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.URL.RequestURI()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job_id":"j-42"}`))
	}))
	defer ez.Close()
	dir := filepath.Join(root, "var", "lib", "hostzit", "import")
	_ = os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, "cpmove-shop.tar.gz"), []byte("archive bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	cust := "0f8fad5b-d9cb-469f-a165-70867728950e"
	r, err := h.importMail(context.Background(), mailImportArgs{File: "cpmove-shop.tar.gz", URL: ez.URL, Token: "ezt_secret", Insecure: true, Customer: cust})
	if err != nil {
		t.Fatal(err)
	}
	if r.(map[string]string)["job_id"] != "j-42" || string(got) != "archive bytes" || auth != "Bearer ezt_secret" || ctype != "application/gzip" ||
		path != "/api/v1/customers/"+cust+"/import?format=cpanel" {
		t.Errorf("job %v, body %q, auth %q, type %q, path %q", r, got, auth, ctype, path)
	}
	// without "insecure" a self-signed EmailZit is refused
	if _, err := h.importMail(context.Background(), mailImportArgs{File: "cpmove-shop.tar.gz", URL: ez.URL, Token: "ezt_secret", Customer: cust}); err == nil {
		t.Error("self-signed certificate accepted")
	}
	for name, a := range map[string]mailImportArgs{
		"path in name": {File: "../etc/shadow", URL: ez.URL, Token: "ezt_x", Customer: cust},
		"bad customer": {File: "cpmove-shop.tar.gz", URL: ez.URL, Token: "ezt_x", Customer: "1; drop"},
		"bad url":      {File: "cpmove-shop.tar.gz", URL: "file:///etc/passwd", Token: "ezt_x", Customer: cust},
		"bad token":    {File: "cpmove-shop.tar.gz", URL: ez.URL, Token: "x\nInjected: 1", Customer: cust},
		"missing file": {File: "cpmove-none.tar.gz", URL: ez.URL, Token: "ezt_x", Insecure: true, Customer: cust},
		"user in url":  {File: "cpmove-shop.tar.gz", URL: "https://a:b@example.com", Token: "ezt_x", Customer: cust},
	} {
		if _, err := h.importMail(context.Background(), a); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
