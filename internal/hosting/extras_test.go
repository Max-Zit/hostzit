package hosting

import (
	"strings"
	"testing"
)

func TestSiteExtrasValidate(t *testing.T) {
	ok := SiteExtras{ErrorPages: map[string]string{"404": "/errors/404.html", "503": "/maintenance.html"}, Indexes: true,
		MimeTypes: map[string]string{"webmanifest": "application/manifest+json", "wasm": "application/wasm"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]SiteExtras{
		"unknown code":       {ErrorPages: map[string]string{"200": "/x.html"}},
		"code not a number":  {ErrorPages: map[string]string{"40x": "/x.html"}},
		"relative page":      {ErrorPages: map[string]string{"404": "x.html"}},
		"page outside":       {ErrorPages: map[string]string{"404": "/../etc/passwd"}},
		"page with space":    {ErrorPages: map[string]string{"404": "/a b.html"}},
		"page with ;":        {ErrorPages: map[string]string{"404": "/a.html;deny"}},
		"php source":         {MimeTypes: map[string]string{"php": "text/plain"}},
		"phtml source":       {MimeTypes: map[string]string{"phtml": "text/plain"}},
		"extension with dot": {MimeTypes: map[string]string{"tar.gz": "application/gzip"}},
		"regex in extension": {MimeTypes: map[string]string{"(x|y)": "text/plain"}},
		"type with ;":        {MimeTypes: map[string]string{"x": "text/plain;charset=utf-8"}},
		"type with space":    {MimeTypes: map[string]string{"x": "text/plain }"}},
		"no slash":           {MimeTypes: map[string]string{"x": "textplain"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestNginxSiteExtras(t *testing.T) {
	s := testSite()
	s.Extras = SiteExtras{ErrorPages: map[string]string{"503": "/m.html", "404": "/404.html"}, Indexes: true, MimeTypes: map[string]string{"webmanifest": "application/manifest+json"}}
	out, err := NginxSite(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"    error_page 404 /404.html;\n    error_page 503 /m.html;\n", "    autoindex on;\n",
		"    location ~* \\.webmanifest$ {\n        types {}\n        default_type application/manifest+json;\n        try_files $uri =404;\n    }\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// the own file types come after the rule for hidden files and before PHP
	hidden, typ, php := strings.Index(out, "location ~ /\\.(?!well-known/)"), strings.Index(out, "\\.webmanifest$"), strings.Index(out, "location ~ \\.php$ {")
	if hidden < 0 || typ < hidden || php < typ {
		t.Errorf("order hidden %d, type %d, php %d", hidden, typ, php)
	}
	// a bad value never reaches the file
	s.Extras.MimeTypes = map[string]string{"php": "text/plain"}
	if _, err := NginxSite(s); err == nil {
		t.Error("php source type rendered")
	}
	// without extras nothing changes
	s.Extras = SiteExtras{}
	out, _ = NginxSite(s)
	if strings.Contains(out, "autoindex") || strings.Contains(out, "error_page 404") || strings.Contains(out, "types {}") {
		t.Errorf("extras without settings:\n%s", out)
	}
}
