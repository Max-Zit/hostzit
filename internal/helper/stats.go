package helper

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Visitor statistics of a website from its nginx access logs (the current
// one and the rotated ones of the last month), counted by GoAccess (MIT).
// Only totals and top lists leave the helper; visitor addresses do not.

// StatItem is a line of a top list.
type StatItem struct {
	Name     string `json:"name"`
	Hits     int64  `json:"hits"`
	Visitors int64  `json:"visitors"`
	Bytes    int64  `json:"bytes"`
}

// SiteStats is the report of a website.
type SiteStats struct {
	From      string     `json:"from"`
	To        string     `json:"to"`
	Requests  int64      `json:"requests"`
	Visitors  int64      `json:"visitors"`
	Bytes     int64      `json:"bytes"`
	NotFound  int64      `json:"not_found"`
	Days      []StatItem `json:"days"` // oldest first, Name = YYYY-MM-DD
	Pages     []StatItem `json:"pages"`
	Missing   []StatItem `json:"missing"`
	Referrers []StatItem `json:"referrers"`
	Browsers  []StatItem `json:"browsers"`
	Systems   []StatItem `json:"systems"`
	Status    []StatItem `json:"status"`
	Crawlers  int64      `json:"crawlers"` // hits of known crawlers
}

type statsArgs struct {
	Account string `json:"account"`
	ID      int64  `json:"id"`
}

// maxStatsInput bounds what one report reads (newest logs first).
const maxStatsInput = 1 << 30

// statLogFiles are the site's access logs, newest first, of the last 31 days.
func statLogFiles(dir string) []string {
	files := []string{dir + "/access.log", dir + "/access.log.1"}
	for i := 2; i <= 31; i++ {
		files = append(files, dir+"/access.log."+strconv.Itoa(i)+".gz")
	}
	var out []string
	for _, f := range files {
		if fi, err := os.Lstat(f); err == nil && fi.Mode().IsRegular() {
			out = append(out, f)
		}
	}
	return out
}

func (h *Helper) siteStats(ctx context.Context, a statsArgs) (any, error) {
	if err := (siteRef{Account: a.Account, ID: a.ID}).check(); err != nil {
		return nil, err
	}
	if !h.Sys.Exists("/usr/bin/goaccess") {
		if out, err := h.apt(ctx, "install", "--no-install-recommends", "goaccess"); err != nil {
			return nil, userErr("GoAccess could not be installed: " + tail(string(out), 300))
		}
	}
	_, logs, _ := siteDirs(a.ID)
	files := statLogFiles(logs)
	if len(files) == 0 {
		return SiteStats{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/goaccess", "-", "--no-global-config", "--no-progress", "--no-query-string", "--ignore-panel=HOSTS", "--ignore-panel=GEO_LOCATION",
		`--log-format=%h - [%x] "%r" %s %b "%R" "%u" %T %^`, "--datetime-format=%Y-%m-%dT%H:%M:%S%z", "-o", "json") // #nosec G204 -- fixed program and arguments
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		defer in.Close()
		w := bufio.NewWriterSize(in, 1<<20)
		defer w.Flush()
		var n int64
		// oldest first, so the days come in order
		for i := len(files) - 1; i >= 0 && n < maxStatsInput; i-- {
			f, err := os.Open(files[i]) // #nosec G304 -- the site's own log under /var/log/hostzit/sites
			if err != nil {
				continue
			}
			var r io.Reader = f
			if strings.HasSuffix(files[i], ".gz") {
				if gz, err := gzip.NewReader(f); err == nil {
					r = gz
				}
			}
			c, _ := io.Copy(w, io.LimitReader(r, maxStatsInput-n))
			n += c
			_ = f.Close()
		}
	}()
	if err := cmd.Wait(); err != nil {
		return nil, userErr("the statistics could not be made: " + err.Error())
	}
	return parseGoAccess([]byte(out.String()))
}

type gaCount struct {
	Count int64 `json:"count"`
}

type gaItem struct {
	Data     string   `json:"data"`
	Hits     gaCount  `json:"hits"`
	Visitors gaCount  `json:"visitors"`
	Bytes    gaCount  `json:"bytes"`
	Items    []gaItem `json:"items"`
}

type gaPanel struct {
	Data []gaItem `json:"data"`
}

func top(p gaPanel, n int) []StatItem {
	out := make([]StatItem, 0, n)
	for _, it := range p.Data {
		if len(out) >= n {
			break
		}
		out = append(out, StatItem{Name: it.Data, Hits: it.Hits.Count, Visitors: it.Visitors.Count, Bytes: it.Bytes.Count})
	}
	return out
}

// parseGoAccess keeps what the panel shows from GoAccess's JSON report.
func parseGoAccess(b []byte) (SiteStats, error) {
	var r struct {
		General struct {
			Start    string `json:"start_date"`
			End      string `json:"end_date"`
			Total    int64  `json:"total_requests"`
			Visitors int64  `json:"unique_visitors"`
			Bytes    int64  `json:"bandwidth"`
		} `json:"general"`
		Visitors  gaPanel `json:"visitors"`
		Requests  gaPanel `json:"requests"`
		NotFound  gaPanel `json:"not_found"`
		Referring gaPanel `json:"referring_sites"`
		Browsers  gaPanel `json:"browsers"`
		OS        gaPanel `json:"os"`
		Status    gaPanel `json:"status_codes"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return SiteStats{}, userErr("the statistics could not be read")
	}
	st := SiteStats{From: r.General.Start, To: r.General.End, Requests: r.General.Total, Visitors: r.General.Visitors, Bytes: r.General.Bytes}
	st.Days = top(r.Visitors, 62)
	for i := range st.Days {
		if d := st.Days[i].Name; len(d) == 8 {
			st.Days[i].Name = d[:4] + "-" + d[4:6] + "-" + d[6:]
		}
	}
	sort.Slice(st.Days, func(i, j int) bool { return st.Days[i].Name < st.Days[j].Name })
	st.Pages = top(r.Requests, 20)
	st.Missing = top(r.NotFound, 10)
	for _, it := range r.NotFound.Data {
		st.NotFound += it.Hits.Count
	}
	st.Referrers = top(r.Referring, 15)
	st.Browsers = top(r.Browsers, 10)
	for _, it := range r.Browsers.Data {
		if it.Data == "Crawlers" {
			st.Crawlers = it.Hits.Count
		}
	}
	st.Systems = top(r.OS, 10)
	st.Status = top(r.Status, 10)
	st.Status = slices.DeleteFunc(st.Status, func(s StatItem) bool { return s.Hits == 0 })
	return st, nil
}

func init() {
	moreOps = append(moreOps, func(h *Helper) {
		h.ops["site.stats"] = op{handle(h.siteStats), false}
	})
}
