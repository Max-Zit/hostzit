package web

import (
	"embed"
	"html"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// The user guide in the console (/docs). Every page is a plain HTML
// fragment in docs/<language>/<page>.html, written by us and embedded, so it
// can be shown as trusted HTML; a page missing in a language is shown in
// English. Search splits the pages at their h2/h3 headings.

//go:embed docs
var docsFS embed.FS

// DocPage is a page of the user guide.
type DocPage struct{ Slug, Title string }

// DocPages lists the guide in reading order.
var DocPages = []DocPage{
	{"start", "Getting started"},
	{"install", "Installing the server"},
	{"customers", "Customers and packages"},
	{"sites", "Websites, PHP and page cache"},
	{"dns", "Domains and DNS"},
	{"databases", "Databases"},
	{"files", "Files, SFTP and SSH"},
	{"wordpress", "WordPress"},
	{"security", "Isolation and security"},
	{"api", "REST API for billing"},
	{"admin", "Users, settings and updates"},
	{"troubleshooting", "Troubleshooting and FAQ"},
}

// docHTML returns a page in lang, or in English.
func docHTML(lang, slug string) template.HTML {
	for _, l := range []string{lang, "en"} {
		if b, err := docsFS.ReadFile("docs/" + l + "/" + slug + ".html"); err == nil {
			return template.HTML(b) // #nosec G203 -- our own embedded guide
		}
	}
	return ""
}

type docsData struct {
	Pages      []DocPage
	Page       string
	Body       template.HTML
	Prev, Next *DocPage
	Q          string
	Hits       []docHit
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("page")
	if slug == "" {
		slug = "start"
	}
	pages := docPagesFor(panelOf(r))
	d := &docsData{Pages: pages, Page: slug}
	title := ""
	for i, p := range pages {
		if p.Slug == slug {
			title = p.Title
			if i > 0 {
				d.Prev = &pages[i-1]
			}
			if i < len(pages)-1 {
				d.Next = &pages[i+1]
			}
		}
	}
	if title == "" {
		s.notFound(w, r)
		return
	}
	lang := s.lang(r, userFrom(r))
	d.Body = docHTML(lang, slug)
	s.render(w, r, http.StatusOK, "docs", &Page{Title: title, Nav: "docs", Lang: lang, Data: d})
}

func (s *Server) handleDocsSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.FormValue("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	lang := s.lang(r, userFrom(r))
	s.render(w, r, http.StatusOK, "docsearch", &Page{Title: "Search the guide", Nav: "docs", Lang: lang,
		Data: &docsData{Pages: docPagesFor(panelOf(r)), Q: q, Hits: filterHits(searchDocs(lang, q), panelOf(r))}})
}

type docSection struct {
	Slug, Page, Heading, Anchor string
	text, lower, lowerHead      string
}

type docHit struct {
	Slug, Page, Heading, Anchor string
	Snippet                     template.HTML
	score                       int
}

var (
	docIndexMu sync.Mutex
	docIndex   = map[string][]docSection{}

	reHeading = regexp.MustCompile(`(?s)<h([23])([^>]*)>(.*?)</h[23]>`)
	reID      = regexp.MustCompile(`\bid="([^"]+)"`)
	reTag     = regexp.MustCompile(`(?s)<[^>]+>`)
	reSpace   = regexp.MustCompile(`\s+`)
)

func plainText(s string) string {
	return strings.TrimSpace(reSpace.ReplaceAllString(html.UnescapeString(reTag.ReplaceAllString(s, " ")), " "))
}

// foldCase lowercases letter by letter, so the result has as many letters
// as s (strings.ToLower turns the Turkish İ into two).
func foldCase(s string) string { return strings.Map(unicode.ToLower, s) }

// docSections splits the guide in lang at its headings (once per language).
func docSections(lang string) []docSection {
	docIndexMu.Lock()
	defer docIndexMu.Unlock()
	if idx, ok := docIndex[lang]; ok {
		return idx
	}
	var idx []docSection
	for _, p := range DocPages {
		body := string(docHTML(lang, p.Slug))
		title := translate(lang, p.Title)
		add := func(heading, anchor, part string) {
			text := plainText(part)
			if text == "" && heading == "" {
				return
			}
			idx = append(idx, docSection{Slug: p.Slug, Page: title, Heading: heading, Anchor: anchor,
				text: text, lower: foldCase(text), lowerHead: foldCase(heading + " " + title)})
		}
		start, heading, anchor := 0, "", ""
		for _, c := range reHeading.FindAllStringSubmatchIndex(body, -1) {
			add(heading, anchor, body[start:c[0]])
			heading = plainText(body[c[6]:c[7]])
			anchor = ""
			if m := reID.FindStringSubmatch(body[c[4]:c[5]]); m != nil {
				anchor = m[1]
			}
			start = c[1]
		}
		add(heading, anchor, body[start:])
	}
	docIndex[lang] = idx
	return idx
}

// searchDocs returns the sections that contain every word of q, best first.
func searchDocs(lang, q string) []docHit {
	var terms []string
	for _, w := range strings.Fields(foldCase(q)) {
		if utf8.RuneCountInString(w) >= 2 && len(terms) < 8 {
			terms = append(terms, w)
		}
	}
	if len(terms) == 0 {
		return nil
	}
	var hits []docHit
	for _, sec := range docSections(lang) {
		score := 0
		for _, t := range terms {
			n := strings.Count(sec.lower, t) + 5*strings.Count(sec.lowerHead, t)
			if n == 0 {
				score = 0
				break
			}
			score += n
		}
		if score > 0 {
			hits = append(hits, docHit{Slug: sec.Slug, Page: sec.Page, Heading: sec.Heading, Anchor: sec.Anchor,
				Snippet: snippet(sec.text, sec.lower, terms), score: score})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	if len(hits) > 30 {
		hits = hits[:30]
	}
	return hits
}

// snippet cuts about 220 letters around the first match and marks the
// words; everything else is escaped. lower is foldCase(text).
func snippet(text, lower string, terms []string) template.HTML {
	tr, lr := []rune(text), []rune(lower)
	if len(lr) != len(tr) {
		lr = []rune(foldCase(text))
	}
	match := func(i int) int {
		best := 0
		for _, t := range terms {
			rt := []rune(t)
			if len(rt) <= best || i+len(rt) > len(lr) {
				continue
			}
			if string(lr[i:i+len(rt)]) == t {
				best = len(rt)
			}
		}
		return best
	}
	first := 0
	for i := range lr {
		if match(i) > 0 {
			first = i
			break
		}
	}
	start, end := max(first-80, 0), min(first+140, len(tr))
	var b strings.Builder
	if start > 0 {
		b.WriteString("… ")
	}
	for i := start; i < end; {
		if n := match(i); n > 0 {
			b.WriteString("<mark>" + template.HTMLEscapeString(string(tr[i:i+n])) + "</mark>")
			i += n
			continue
		}
		b.WriteString(template.HTMLEscapeString(string(tr[i])))
		i++
	}
	if end < len(tr) {
		b.WriteString(" …")
	}
	return template.HTML(b.String()) // #nosec G203 -- every piece is escaped above
}

// adminDocs are the guide pages only administrators see.
var adminDocs = map[string]bool{"install": true, "customers": true, "api": true, "admin": true}

// docPagesFor lists the guide pages of a panel.
func docPagesFor(panel string) []DocPage {
	if panel == PanelAdmin {
		return DocPages
	}
	var out []DocPage
	for _, p := range DocPages {
		if !adminDocs[p.Slug] {
			out = append(out, p)
		}
	}
	return out
}

func filterHits(h []docHit, panel string) []docHit {
	if panel == PanelAdmin {
		return h
	}
	out := h[:0]
	for _, x := range h {
		if !adminDocs[x.Slug] {
			out = append(out, x)
		}
	}
	return out
}
