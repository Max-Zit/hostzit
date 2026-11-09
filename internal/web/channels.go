package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Notification channels besides e-mail (Settings → Notifications): a
// webhook (JSON POST, e.g. to a chat or monitoring system) and Telegram.
// They get the administrators' notices; customers are told by e-mail only.

const settingChannels = "notify_channels"

// ChannelSettings are the other channels of the notices.
type ChannelSettings struct {
	Webhook       string `json:"webhook,omitempty"`
	TelegramToken string `json:"telegram_token,omitempty"` // sealed
	TelegramChat  string `json:"telegram_chat,omitempty"`
}

var (
	telegramTokenRE = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{30,64}$`)
	telegramChatRE  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
)

// telegramAPI is Telegram's Bot API (tests point it elsewhere).
var telegramAPI = "https://api.telegram.org"

func init() {
	adminExtra = append(adminExtra, func(s *Server, mux *http.ServeMux, app, write, admin func(string, http.HandlerFunc)) {
		admin("POST /settings/mail/channels", s.handleChannelsSave)
		admin("POST /settings/mail/channels/test", s.handleChannelsTest)
	})
}

func (s *Server) channelSettings(ctx context.Context) ChannelSettings {
	var c ChannelSettings
	_ = s.store.GetSetting(ctx, settingChannels, &c)
	return c
}

// webhookPayload is what the webhook gets.
type webhookPayload struct {
	Product  string    `json:"product"`
	Server   string    `json:"server"`
	Kind     string    `json:"kind"`
	Key      string    `json:"key"`
	Customer string    `json:"customer,omitempty"`
	Subject  string    `json:"subject"`
	Text     string    `json:"text"`
	Time     time.Time `json:"time"`
}

// sendChannels delivers a notice to the webhook and Telegram; the errors of
// both are joined.
func (s *Server) sendChannels(ctx context.Context, key, customer, subject, body string) error {
	ch := s.channelSettings(ctx)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	hc := &http.Client{Timeout: 20 * time.Second}
	var errs []error
	server := s.hostingSettings(ctx).ServerName
	if ch.Webhook != "" {
		p := webhookPayload{Product: "hostzit", Server: server, Kind: noticeKind(key), Key: key, Customer: customer, Subject: subject, Text: body, Time: s.now().UTC()}
		b, _ := json.Marshal(p)
		if err := post(ctx, hc, ch.Webhook, "application/json", b); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}
	if ch.TelegramToken != "" && ch.TelegramChat != "" {
		tok, err := s.store.OpenSecret("telegram.token", ch.TelegramToken)
		if err == nil {
			text := subject + "\n\n" + body
			if server != "" {
				text = "[" + server + "] " + text
			}
			if len(text) > 4000 {
				text = text[:4000]
			}
			form := url.Values{"chat_id": {ch.TelegramChat}, "text": {text}, "disable_web_page_preview": {"true"}}
			err = post(ctx, hc, telegramAPI+"/bot"+tok+"/sendMessage", "application/x-www-form-urlencoded", []byte(form.Encode()))
		}
		if err != nil {
			// the token is part of the address: never put the error's URL in a log
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			errs = append(errs, fmt.Errorf("telegram: %w", err))
		}
	}
	return errors.Join(errs...)
}

func post(ctx context.Context, hc *http.Client, u, ctype string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "HostZit notifications")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("answer %d", resp.StatusCode)
	}
	return nil
}

func validWebhook(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "https" || p.Scheme == "http") && p.Host != "" && p.User == nil && len(u) <= 1000 && !strings.ContainsAny(u, " \r\n")
}

func (s *Server) handleChannelsSave(w http.ResponseWriter, r *http.Request) {
	old := s.channelSettings(r.Context())
	ch := ChannelSettings{Webhook: strings.TrimSpace(r.FormValue("webhook")), TelegramChat: strings.TrimSpace(r.FormValue("telegram_chat")), TelegramToken: old.TelegramToken}
	if ch.Webhook != "" && !validWebhook(ch.Webhook) {
		s.redirectErr(w, r, "/settings/mail", "The webhook must be an http(s) address.")
		return
	}
	if tok := strings.TrimSpace(r.FormValue("telegram_token")); tok != "" {
		if !telegramTokenRE.MatchString(tok) {
			s.redirectErr(w, r, "/settings/mail", "This is not a Telegram bot token (from @BotFather, like 123456:ABC…).")
			return
		}
		ch.TelegramToken = s.store.SealSecret("telegram.token", tok)
	}
	if r.FormValue("telegram_off") != "" {
		ch.TelegramToken, ch.TelegramChat = "", ""
	}
	if ch.TelegramChat != "" && !telegramChatRE.MatchString(ch.TelegramChat) {
		s.redirectErr(w, r, "/settings/mail", "The Telegram chat is a number (like -1001234567890) or @channel.")
		return
	}
	if err := s.store.SetSetting(r.Context(), settingChannels, ch); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.channels", "settings", "webhook %t, telegram %t", ch.Webhook != "", ch.TelegramToken != "" && ch.TelegramChat != "")
	s.redirect(w, r, "/settings/mail", "Saved.")
}

func (s *Server) handleChannelsTest(w http.ResponseWriter, r *http.Request) {
	ch := s.channelSettings(r.Context())
	if ch.Webhook == "" && (ch.TelegramToken == "" || ch.TelegramChat == "") {
		s.redirectErr(w, r, "/settings/mail", "Enter a webhook or a Telegram bot first.")
		return
	}
	if err := s.sendChannels(r.Context(), "test", "", "HostZit test message", "This is a test message from the HostZit panel. Notifications work."); err != nil {
		s.redirectErr(w, r, "/settings/mail", err.Error())
		return
	}
	s.redirect(w, r, "/settings/mail", "The test message was sent.")
}
