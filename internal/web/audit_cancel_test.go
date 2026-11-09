package web

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/max-zit/hostzit/internal/store"
)

// A client that drops the connection right after a change (found by the
// ZAP scan of 0.9.3: "audit log write failed … context canceled") must
// still leave the change in the audit log.
func TestAuditSurvivesDroppedClient(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("POST", "/sites/1", nil).WithContext(ctx)
	cancel()
	e.srv.auditAs(r, "zapshop", "cron.add", "site:x.test", "job added after the client left")
	l, err := e.srv.store.AuditEntries(context.Background(), store.AuditFilter{Query: "client left"})
	if err != nil || len(l) != 1 || l[0].Action != "cron.add" {
		t.Fatalf("audit entries %+v, %v", l, err)
	}
}
