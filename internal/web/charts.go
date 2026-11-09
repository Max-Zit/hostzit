package web

import (
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/max-zit/hostzit/internal/store"
)

// Usage history graphs (customer panel → Usage, admin → the customer):
// disk, memory, CPU and disk speed over 24 hours to 90 days, drawn on the
// server as SVG (no script, no outside library).

// usageRanges are the choices of the graphs ("" = 7 days).
var usageRanges = []struct {
	Key   string
	Label string
	Span  time.Duration
}{
	{"1d", "24 hours", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
	{"90d", "90 days", 90 * 24 * time.Hour},
}

func usageRange(r *http.Request) (string, time.Duration) {
	k := r.URL.Query().Get("range")
	for _, x := range usageRanges {
		if x.Key == k {
			return x.Key, x.Span
		}
	}
	return "7d", 7 * 24 * time.Hour
}

// point is one value of a graph.
type point struct {
	At time.Time
	V  float64
}

// chart is one graph ready for the template.
type chart struct {
	Title string
	SVG   template.HTML
	Max   string // the highest value, with its unit
	Now   string // the newest value
	Limit string // the package limit, when there is one
}

// maxPoints is how many points a graph draws at most; longer ranges are
// reduced to the highest value of each bucket (a peak must stay visible).
const maxPoints = 240

func downsample(p []point) []point {
	if len(p) <= maxPoints {
		return p
	}
	out := make([]point, 0, maxPoints)
	size := float64(len(p)) / maxPoints
	for i := 0; i < maxPoints; i++ {
		from, to := int(float64(i)*size), int(float64(i+1)*size)
		if to > len(p) {
			to = len(p)
		}
		best := p[from]
		for _, x := range p[from:to] {
			if x.V > best.V {
				best = x
			}
		}
		out = append(out, point{At: p[to-1].At, V: best.V})
	}
	return out
}

// drawChart draws the points between from and to; limit > 0 adds a dashed
// line for the package limit.
func drawChart(p []point, from, to time.Time, limit float64) template.HTML {
	if len(p) < 2 || !to.After(from) {
		return ""
	}
	p = downsample(p)
	mx := limit
	for _, x := range p {
		mx = math.Max(mx, x.V)
	}
	if mx <= 0 {
		mx = 1
	}
	const w, h = 600.0, 120.0
	span := to.Sub(from).Seconds()
	xy := func(x point) (float64, float64) {
		return math.Max(0, math.Min(w, x.At.Sub(from).Seconds()*w/span)), h - 2 - x.V*(h-6)/mx
	}
	var line strings.Builder
	for _, x := range p {
		px, py := xy(x)
		fmt.Fprintf(&line, "%.1f,%.1f ", px, py)
	}
	x0, _ := xy(p[0])
	x1, _ := xy(p[len(p)-1])
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" role="img" aria-hidden="true">`, w, h)
	fmt.Fprintf(&b, `<polygon class="area" points="%.1f,%.0f %s%.1f,%.0f"/>`, x0, h, line.String(), x1, h)
	fmt.Fprintf(&b, `<polyline points="%s"/>`, strings.TrimSpace(line.String()))
	if limit > 0 {
		ly := h - 2 - limit*(h-6)/mx
		fmt.Fprintf(&b, `<line class="limit" x1="0" y1="%.1f" x2="%.0f" y2="%.1f"/>`, ly, w, ly)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) // #nosec G203 -- numbers only
}

// usageCharts builds the four graphs of a customer for a range.
func usageCharts(samples []store.UsageSample, p *store.Package, from, to time.Time) []chart {
	if len(samples) < 2 {
		return nil
	}
	var disk, mem, cpu, io []point
	for _, u := range samples {
		disk = append(disk, point{u.At, float64(u.DiskKB) / 1024})
		mem = append(mem, point{u.At, float64(u.MemoryB) / (1 << 20)})
	}
	for _, r := range store.Rates(samples) {
		cpu = append(cpu, point{r.At, r.CPUPercent})
		io = append(io, point{r.At, r.IOMBps})
	}
	var lDisk, lMem, lCPU, lIO float64
	if p != nil {
		lDisk, lMem, lCPU, lIO = float64(p.Limits.DiskMB), float64(p.Limits.MemoryMB), float64(p.Limits.CPUPercent), float64(p.Limits.IOMBps)
	}
	mk := func(title string, pts []point, limit float64, format func(float64) string) chart {
		c := chart{Title: title, SVG: drawChart(pts, from, to, limit)}
		if len(pts) > 0 {
			var mx float64
			for _, x := range pts {
				mx = math.Max(mx, x.V)
			}
			c.Max, c.Now = format(mx), format(pts[len(pts)-1].V)
		}
		if limit > 0 {
			c.Limit = format(limit)
		}
		return c
	}
	mb := func(v float64) string {
		if v >= 1024 {
			return fmt.Sprintf("%.1f GB", v/1024)
		}
		return fmt.Sprintf("%.0f MB", v)
	}
	return []chart{
		mk("Disk", disk, lDisk, mb),
		mk("Memory", mem, lMem, mb),
		mk("CPU (%)", cpu, lCPU, func(v float64) string { return fmt.Sprintf("%.0f %%", v) }),
		mk("Disk speed", io, lIO, func(v float64) string { return fmt.Sprintf("%.1f MB/s", v) }),
	}
}

// usageHistory is the graph section of a page.
type usageHistory struct {
	Range  string
	Ranges []rangeLink
	Charts []chart
	From   time.Time
	To     time.Time
}

type rangeLink struct {
	Key, Label, URL string
	On              bool
}

// history loads the samples of a customer for the page's range.
func (s *Server) history(r *http.Request, c *store.Customer, p *store.Package, base string) usageHistory {
	key, span := usageRange(r)
	to := s.now()
	from := to.Add(-span)
	samples, _ := s.store.Usage(r.Context(), c.ID, from)
	h := usageHistory{Range: key, Charts: usageCharts(samples, p, from, to), From: from, To: to}
	for _, x := range usageRanges {
		h.Ranges = append(h.Ranges, rangeLink{Key: x.Key, Label: x.Label, URL: base + "?range=" + x.Key, On: x.Key == key})
	}
	return h
}
