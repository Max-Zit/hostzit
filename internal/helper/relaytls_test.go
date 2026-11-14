package helper

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// EmailZit's relay with its own self-signed certificate is accepted with the
// pin of the pairing code, and refused with another pin or none.
func TestRelayTLSPin(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS()
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	good := base64.StdEncoding.EncodeToString(sum[:])
	other := sha256.Sum256([]byte("another key"))
	dial := func(pin string) error {
		c, err := tls.Dial("tcp", srv.Listener.Addr().String(), relayTLS(RelayConfig{Host: "mail-a.lab.test", Pin: pin}))
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := dial(good); err != nil {
		t.Fatalf("pinned key refused: %v", err)
	}
	if err := dial(base64.StdEncoding.EncodeToString(other[:])); err == nil {
		t.Fatal("another key accepted")
	}
	if err := dial(""); err == nil {
		t.Fatal("an untrusted certificate without a pin accepted")
	}
}
