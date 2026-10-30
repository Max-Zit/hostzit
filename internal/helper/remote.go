package helper

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Remote backup destinations: an SFTP server or an S3-compatible bucket
// (AWS, MinIO, Wasabi, Backblaze B2 …). The helper uploads the archives,
// because only root can read them; the panel keeps the settings and passes
// the credentials with each request.

// RemoteDest is where the backups go.
type RemoteDest struct {
	Type string `json:"type"` // sftp | s3
	// SFTP
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"`      // private key (PEM)
	HostKey  string `json:"host_key,omitempty"` // SHA256:… ("" = learn it)
	// S3
	Endpoint  string `json:"endpoint,omitempty"` // "" = AWS
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	// Path is the folder (SFTP) or key prefix (S3) of the backups.
	Path string `json:"path,omitempty"`
}

type remoteStore interface {
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	List(ctx context.Context, prefix string) ([]remoteObject, error)
	Get(ctx context.Context, key string, w io.Writer) error
	Delete(ctx context.Context, key string) error
	Close() error
}

type remoteObject struct {
	Key  string    `json:"key"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

// key is the object name below the configured path.
func (d RemoteDest) key(parts ...string) string {
	p := strings.Trim(d.Path, "/")
	if p != "" {
		parts = append([]string{p}, parts...)
	}
	return strings.Join(parts, "/")
}

// open connects to the destination; for SFTP it also reports the host key.
func (d RemoteDest) open(ctx context.Context) (remoteStore, string, error) {
	switch d.Type {
	case "sftp":
		return openSFTP(ctx, d)
	case "s3":
		if d.Bucket == "" || d.AccessKey == "" || d.SecretKey == "" {
			return nil, "", userErr("enter the bucket and the access keys")
		}
		if d.Region == "" {
			d.Region = "us-east-1"
		}
		return &s3Store{d: d, c: &http.Client{Timeout: 0}}, "", nil
	}
	return nil, "", userErr("choose SFTP or S3")
}

// ---- SFTP

type sftpStore struct {
	conn *ssh.Client
	c    *sftp.Client
}

func openSFTP(ctx context.Context, d RemoteDest) (remoteStore, string, error) {
	if d.Host == "" || d.User == "" {
		return nil, "", userErr("enter the server and the user")
	}
	if d.Port == 0 {
		d.Port = 22
	}
	var auth []ssh.AuthMethod
	if d.Key != "" {
		k, err := ssh.ParsePrivateKey([]byte(d.Key))
		if err != nil {
			return nil, "", userErr("the private key cannot be read")
		}
		auth = append(auth, ssh.PublicKeys(k))
	}
	if d.Password != "" {
		auth = append(auth, ssh.Password(d.Password))
	}
	seen := ""
	cfg := &ssh.ClientConfig{User: d.User, Auth: auth, Timeout: 20 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(k)
			if d.HostKey != "" && d.HostKey != seen {
				return fmt.Errorf("the server's host key changed (%s, expected %s)", seen, d.HostKey)
			}
			return nil
		}}
	addr := net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	var dl net.Dialer
	raw, err := dl.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, seen, userErr("cannot connect: " + err.Error())
	}
	sc, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		return nil, seen, userErr("SSH: " + err.Error())
	}
	conn := ssh.NewClient(sc, chans, reqs)
	c, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, seen, userErr("SFTP: " + err.Error())
	}
	return &sftpStore{conn: conn, c: c}, seen, nil
}

func (s *sftpStore) Put(_ context.Context, key string, r io.Reader, _ int64) error {
	if err := s.c.MkdirAll(path.Dir(key)); err != nil {
		return err
	}
	tmp := key + ".part"
	f, err := s.c.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.ReadFrom(r); err != nil {
		_ = f.Close()
		_ = s.c.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_ = s.c.Remove(key)
	return s.c.Rename(tmp, key)
}

func (s *sftpStore) List(_ context.Context, prefix string) ([]remoteObject, error) {
	ents, err := s.c.ReadDir(strings.TrimSuffix(prefix, "/"))
	if err != nil {
		if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "not exist") {
			return nil, nil
		}
		return nil, err
	}
	var out []remoteObject
	for _, e := range ents {
		if e.Mode().IsRegular() {
			out = append(out, remoteObject{Key: strings.TrimSuffix(prefix, "/") + "/" + e.Name(), Size: e.Size(), Time: e.ModTime()})
		}
	}
	return out, nil
}

func (s *sftpStore) Get(_ context.Context, key string, w io.Writer) error {
	f, err := s.c.Open(key)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteTo(w)
	return err
}

func (s *sftpStore) Delete(_ context.Context, key string) error { return s.c.Remove(key) }

func (s *sftpStore) Close() error {
	_ = s.c.Close()
	return s.conn.Close()
}

// ---- S3 (signature version 4)

type s3Store struct {
	d RemoteDest
	c *http.Client
}

const s3PartSize = 64 << 20

// url is the object's address: path style for a custom endpoint, the
// bucket's own host name on AWS.
func (s *s3Store) url(key string, q url.Values) (*url.URL, error) {
	var u *url.URL
	var err error
	if s.d.Endpoint == "" {
		u, err = url.Parse("https://" + s.d.Bucket + ".s3." + s.d.Region + ".amazonaws.com/" + key)
	} else {
		u, err = url.Parse(strings.TrimRight(s.d.Endpoint, "/") + "/" + s.d.Bucket + "/" + key)
	}
	if err != nil {
		return nil, err
	}
	if q != nil {
		u.RawQuery = s3Query(q)
	}
	return u, nil
}

// s3Escape encodes like AWS wants it (RFC 3986 unreserved stay).
func s3Escape(s string, keepSlash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func s3Query(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, s3Escape(k, false)+"="+s3Escape(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// sign adds the SigV4 authorization to a request; payload is the hex
// SHA-256 of the body or UNSIGNED-PAYLOAD.
func (s *s3Store) sign(req *http.Request, payload string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payload)
	host := req.URL.Host
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonHeaders := "host:" + host + "\nx-amz-content-sha256:" + payload + "\nx-amz-date:" + amzDate + "\n"
	canon := strings.Join([]string{req.Method, s3Escape(req.URL.Path, true), req.URL.RawQuery, canonHeaders, strings.Join(signed, ";"), payload}, "\n")
	scope := date + "/" + s.d.Region + "/s3/aws4_request"
	h := sha256.Sum256([]byte(canon))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	k := hmacSHA256([]byte("AWS4"+s.d.SecretKey), date)
	k = hmacSHA256(k, s.d.Region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.d.AccessKey+"/"+scope+", SignedHeaders="+strings.Join(signed, ";")+", Signature="+hex.EncodeToString(hmacSHA256(k, toSign)))
}

// do sends a request; body may be nil. small bodies are hashed, streams
// (size >= 0 and unsigned) go as UNSIGNED-PAYLOAD.
func (s *s3Store) do(ctx context.Context, method, key string, q url.Values, body io.Reader, size int64, small []byte) (*http.Response, error) {
	u, err := s.url(key, q)
	if err != nil {
		return nil, err
	}
	payload := "UNSIGNED-PAYLOAD"
	if body == nil {
		sum := sha256.Sum256(small)
		payload = hex.EncodeToString(sum[:])
		body = bytes.NewReader(small)
		size = int64(len(small))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	s.sign(req, payload, time.Now())
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		var e struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		}
		_ = xml.Unmarshal(b, &e)
		if e.Code != "" {
			return nil, fmt.Errorf("S3 %s: %s (%s)", method, e.Message, e.Code)
		}
		return nil, fmt.Errorf("S3 %s: HTTP %d", method, resp.StatusCode)
	}
	return resp, nil
}

func (s *s3Store) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if size <= s3PartSize {
		resp, err := s.do(ctx, http.MethodPut, key, nil, r, size, nil)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	// multipart upload in parts of 64 MiB
	resp, err := s.do(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, nil, 0, []byte{})
	if err != nil {
		return err
	}
	var init struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&init)
	_ = resp.Body.Close()
	if err != nil || init.UploadID == "" {
		return errors.New("S3: no upload id")
	}
	abort := func() {
		if r, err := s.do(context.Background(), http.MethodDelete, key, url.Values{"uploadId": {init.UploadID}}, nil, 0, []byte{}); err == nil {
			_ = r.Body.Close()
		}
	}
	var parts strings.Builder
	parts.WriteString("<CompleteMultipartUpload>")
	buf := make([]byte, s3PartSize)
	for n := 1; ; n++ {
		m, rerr := io.ReadFull(r, buf)
		if m > 0 {
			q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {init.UploadID}}
			resp, err := s.do(ctx, http.MethodPut, key, q, bytes.NewReader(buf[:m]), int64(m), nil)
			if err != nil {
				abort()
				return err
			}
			_ = resp.Body.Close()
			fmt.Fprintf(&parts, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", n, resp.Header.Get("ETag"))
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			abort()
			return rerr
		}
	}
	parts.WriteString("</CompleteMultipartUpload>")
	resp, err = s.do(ctx, http.MethodPost, key, url.Values{"uploadId": {init.UploadID}}, nil, 0, []byte(parts.String()))
	if err != nil {
		abort()
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (s *s3Store) List(ctx context.Context, prefix string) ([]remoteObject, error) {
	var out []remoteObject
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := s.do(ctx, http.MethodGet, "", q, nil, 0, []byte{})
		if err != nil {
			return nil, err
		}
		var res struct {
			Contents []struct {
				Key          string    `xml:"Key"`
				Size         int64     `xml:"Size"`
				LastModified time.Time `xml:"LastModified"`
			} `xml:"Contents"`
			IsTruncated bool   `xml:"IsTruncated"`
			NextToken   string `xml:"NextContinuationToken"`
		}
		err = xml.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&res)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		for _, c := range res.Contents {
			out = append(out, remoteObject{Key: c.Key, Size: c.Size, Time: c.LastModified})
		}
		if !res.IsTruncated || res.NextToken == "" {
			return out, nil
		}
		token = res.NextToken
	}
}

func (s *s3Store) Get(ctx context.Context, key string, w io.Writer) error {
	resp, err := s.do(ctx, http.MethodGet, key, nil, nil, 0, []byte{})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return err
}

func (s *s3Store) Delete(ctx context.Context, key string) error {
	resp, err := s.do(ctx, http.MethodDelete, key, nil, nil, 0, []byte{})
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (s *s3Store) Close() error { return nil }

// createBucket makes the bucket (outside us-east-1 with its region).
func (s *s3Store) createBucket(ctx context.Context) error {
	body := []byte{}
	if s.d.Region != "us-east-1" {
		body = []byte("<CreateBucketConfiguration><LocationConstraint>" + s.d.Region + "</LocationConstraint></CreateBucketConfiguration>")
	}
	resp, err := s.do(ctx, http.MethodPut, "", nil, nil, 0, body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}
