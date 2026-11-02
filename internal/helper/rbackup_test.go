package helper

import (
	"strings"
	"testing"
)

func TestCleanRel(t *testing.T) {
	for in, want := range map[string]string{"": "", "/": "", "sites/a": "sites/a", "/sites//a/": "sites/a", "a/./b": "a/b"} {
		if got, err := cleanRel(in); err != nil || got != want {
			t.Errorf("cleanRel(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"..", "../etc", "a/../../b"} {
		if _, err := cleanRel(bad); err == nil {
			t.Errorf("cleanRel(%q) accepted", bad)
		}
	}
}

func TestResticCmd(t *testing.T) {
	h := New(&OS{Root: t.TempDir(), Runner: nil})
	argv, err := h.resticCmd(RemoteDest{Type: "local", Path: "/var/backups/hostzit"}, "snapshots")
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--repo /var/backups/hostzit/restic snapshots") {
		t.Fatalf("local: %v %v", argv, err)
	}
	argv, _ = h.resticCmd(RemoteDest{Type: "sftp", Host: "b.example", User: "u", Key: "k", Path: "hz", Port: 2222})
	j := strings.Join(argv, " ")
	if !strings.Contains(j, "sftp:u@b.example:hz/restic") || !strings.Contains(j, "-p 2222") || !strings.Contains(j, "StrictHostKeyChecking=accept-new") {
		t.Fatalf("sftp: %s", j)
	}
	argv, _ = h.resticCmd(RemoteDest{Type: "s3", Bucket: "bk", AccessKey: "a", SecretKey: "s", Path: "p"})
	if j := strings.Join(argv, " "); !strings.Contains(j, "s3:https://s3.amazonaws.com/bk/p/restic") || !strings.Contains(j, "AWS_SECRET_ACCESS_KEY=s") {
		t.Fatalf("s3: %s", j)
	}
	for _, bad := range []RemoteDest{{Type: "local", Path: "/"}, {Type: "local", Path: "/home/x"}, {Type: "sftp", Host: "h", User: "u"}, {Type: "s3", Bucket: "b"}, {Type: "ftp"}} {
		if _, err := h.resticCmd(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
