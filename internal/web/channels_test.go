package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestNotifyChannels(t *testing.T) {
	var mu sync.Mutex
	var hooks []webhookPayload
	var tg []url.Values
	var tgPath string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p webhookPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		mu.Lock()
		hooks = append(hooks, p)
		mu.Unlock()
	}))
	defer hook.Close()
	tele := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		mu.Lock()
		tg = append(tg, v)
		tgPath = r.URL.Path
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer tele.Close()
	old := telegramAPI
	telegramAPI = tele.URL
	t.Cleanup(func() { telegramAPI = old })

	e := newEnv(t)
	a := e.setupAdmin()
	token := "123456789:AAH" + strings.Repeat("x", 32)
	// wrong values are refused
	for _, bad := range []url.Values{{"webhook": {"ftp://x.example/"}}, {"telegram_token": {"nope"}, "telegram_chat": {"1"}}, {"telegram_chat": {"chat with space"}}} {
		if st, _, loc := a.post("/settings/mail/channels", bad); st != http.StatusSeeOther || loc != "/settings/mail" {
			t.Errorf("%v: %d %s", bad, st, loc)
		}
	}
	if ch := e.srv.channelSettings(context.Background()); ch.Webhook != "" || ch.TelegramToken != "" {
		t.Fatalf("bad values stored: %+v", ch)
	}
	a.ok("/settings/mail/channels", url.Values{"webhook": {hook.URL + "/hz"}, "telegram_token": {token}, "telegram_chat": {"-1001234567890"}})
	ch := e.srv.channelSettings(context.Background())
	if ch.TelegramToken == token || ch.TelegramToken == "" {
		t.Fatal("the bot token is not sealed")
	}
	if strings.Contains(a.page("/settings/mail"), token) {
		t.Fatal("the bot token is shown on the page")
	}
	// a notice without an SMTP server still reaches both channels
	e.srv.notify(context.Background(), "disk:shop", nil, "Disk space of shop is almost full", "The account uses 95 %.")
	mu.Lock()
	if len(hooks) != 1 || hooks[0].Kind != "disk" || hooks[0].Product != "hostzit" || hooks[0].Subject != "Disk space of shop is almost full" {
		t.Errorf("webhook got %+v", hooks)
	}
	if len(tg) != 1 || tg[0].Get("chat_id") != "-1001234567890" || !strings.Contains(tg[0].Get("text"), "95 %") || tgPath != "/bot"+token+"/sendMessage" {
		t.Errorf("telegram got %v at %s", tg, tgPath)
	}
	mu.Unlock()
	// once a day per notice
	e.srv.notify(context.Background(), "disk:shop", nil, "Disk space of shop is almost full", "again")
	mu.Lock()
	if len(hooks) != 1 {
		t.Errorf("the same notice was sent twice: %d", len(hooks))
	}
	mu.Unlock()
	// test button
	a.ok("/settings/mail/channels/test", url.Values{})
	mu.Lock()
	if len(hooks) != 2 || hooks[1].Kind != "test" || len(tg) != 2 {
		t.Errorf("test message: %d webhook, %d telegram", len(hooks), len(tg))
	}
	mu.Unlock()
	// saving without a token keeps it; "remove" drops the bot
	a.ok("/settings/mail/channels", url.Values{"webhook": {hook.URL + "/hz"}, "telegram_chat": {"-1001234567890"}})
	if e.srv.channelSettings(context.Background()).TelegramToken != ch.TelegramToken {
		t.Error("the token was lost")
	}
	a.ok("/settings/mail/channels", url.Values{"webhook": {""}, "telegram_off": {"on"}})
	if c := e.srv.channelSettings(context.Background()); c.TelegramToken != "" || c.Webhook != "" {
		t.Errorf("not removed: %+v", c)
	}
}
