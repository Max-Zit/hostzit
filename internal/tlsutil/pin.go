package tlsutil

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// PinnedConfig is a client configuration for the other product of a link
// (EmailZit): a certificate chain the system trusts for host is accepted,
// and so is a leaf whose public key has the SHA-256 pin (base64, as in the
// pairing code). An empty pin means the usual check only.
func PinnedConfig(host, pin string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin == "" {
		return cfg
	}
	want, _ := base64.StdEncoding.DecodeString(pin)
	// #nosec G402 -- verified in VerifyConnection (every handshake, also a
	// resumed one): a chain the system trusts for the host name, or the
	// public key pinned by the pairing code
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		raw := make([][]byte, 0, len(cs.PeerCertificates))
		for _, c := range cs.PeerCertificates {
			raw = append(raw, c.Raw)
		}
		return VerifyPinned(raw, host, want)
	}
	return cfg
}

// VerifyPinned accepts a chain the system trusts for host, or a leaf whose
// public key matches pin (a raw SHA-256).
func VerifyPinned(raw [][]byte, host string, pin []byte) error {
	if len(raw) == 0 {
		return errors.New("no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for _, b := range raw {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err == nil {
		return nil
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	if len(pin) == sha256.Size && subtle.ConstantTimeCompare(sum[:], pin) == 1 {
		return nil
	}
	return errors.New("the certificate is neither trusted nor the pinned one")
}

// SPKIPin is the pin of a certificate (base64 SHA-256 of its public key).
func SPKIPin(der []byte) string {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
