package hosting

import (
	"fmt"
	"strconv"
	"strings"
)

// Paths the nginx configuration uses.
const (
	NginxSitesDir    = "/etc/nginx/zit.d/hostzit/sites"     // <account>/<site id>.conf
	NginxCacheZones  = "/etc/nginx/zit.d/hostzit/cache"     // <site id>.conf (http level)
	CacheDir         = "/var/cache/hostzit/pages"           // <site id>/
	CertDir          = "/var/lib/hostzit/certs"             // <site id>/fullchain.pem, privkey.pem
	SiteLogDir       = "/var/log/hostzit/sites"             // <site id>/access.log, error.log
	ACMEChallengeDir = "/var/lib/zit-acme/challenges"       // shared with EmailZit
	SuspendedPage    = "/usr/share/hostzit/suspended"       // index.html
)

// SiteConfPath is the nginx file of a site.
func SiteConfPath(s Site) string {
	return fmt.Sprintf("%s/%s/%d.conf", NginxSitesDir, s.Account, s.ID)
}

// CacheZoneName is the cache zone of a site.
func CacheZoneName(id int64) string { return "hz" + strconv.FormatInt(id, 10) }

// CacheZoneConf is the http-level line that declares the page cache of a
// site (empty when the cache is off).
func CacheZoneConf(s Site) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	if !s.Cache {
		return "", nil
	}
	// 512 KB of keys hold about 4000 pages; files expire after the
	// lifetime (inactive) and the zone never grows beyond 1 GB on disk.
	return fmt.Sprintf("# HostZit page cache of %s (generated, do not edit)\nfastcgi_cache_path %s/%d levels=1:2 keys_zone=%s:512k max_size=1g inactive=%dm use_temp_path=off;\n",
		s.Domain, CacheDir, s.ID, CacheZoneName(s.ID), max(s.CacheMinutes, 10)), nil
}

// NginxSite renders the server blocks of a site. Every value was validated
// by Site.Validate (domains, paths, redirects); nothing is escaped because
// nothing that needs escaping is accepted.
func NginxSite(s Site) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	names := strings.Join(s.Names(), " ")
	root := HomeDir(s.Account) + "/" + s.DocRoot
	logs := fmt.Sprintf("%s/%d", SiteLogDir, s.ID)
	sock := PHPSocket(s.Account, s.PHPVersion)

	w("# HostZit site %s of account %s (generated, do not edit)\n", s.Domain, s.Account)
	httpOnlyRedirect := s.TLS && s.ForceHTTPS
	// Port 80: ACME challenges always; the rest redirects to HTTPS or is
	// the site itself.
	w("server {\n    listen 80;\n    listen [::]:80;\n    server_name %s;\n", names)
	w("    access_log %s/access.log hostzit;\n    error_log %s/error.log warn;\n", logs, logs)
	w("    location ^~ /.well-known/acme-challenge/ {\n        alias %s/;\n        default_type text/plain;\n        try_files $uri =404;\n    }\n", ACMEChallengeDir)
	if httpOnlyRedirect {
		w("    location / {\n        return 301 https://$host$request_uri;\n    }\n}\n")
	} else {
		siteBody(&b, s, root, sock)
		w("}\n")
	}
	if s.TLS {
		cert := fmt.Sprintf("%s/%d", CertDir, s.ID)
		w("server {\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    listen 443 quic;\n    listen [::]:443 quic;\n    http2 on;\n    server_name %s;\n", names)
		w("    ssl_certificate %s/fullchain.pem;\n    ssl_certificate_key %s/privkey.pem;\n", cert, cert)
		w("    add_header Alt-Svc 'h3=\":443\"; ma=86400' always;\n")
		if s.HSTS {
			w("    add_header Strict-Transport-Security \"max-age=31536000\" always;\n")
		}
		w("    access_log %s/access.log hostzit;\n    error_log %s/error.log warn;\n", logs, logs)
		w("    location ^~ /.well-known/acme-challenge/ {\n        alias %s/;\n        default_type text/plain;\n        try_files $uri =404;\n    }\n", ACMEChallengeDir)
		siteBody(&b, s, root, sock)
		w("}\n")
	}
	return b.String(), nil
}

// siteBody writes the part shared by the HTTP and HTTPS server blocks.
func siteBody(b *strings.Builder, s Site, root, sock string) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	if s.Suspended {
		w("    root %s;\n    location / {\n        try_files /index.html =503;\n    }\n    error_page 503 /index.html;\n", SuspendedPage)
		return
	}
	scheme := "$scheme"
	if s.TLS && s.ForceHTTPS {
		scheme = "https"
	}
	switch s.Canonical {
	case "www":
		w("    if ($host = %s) {\n        return 301 %s://www.%s$request_uri;\n    }\n", s.Domain, scheme, s.Domain)
	case "bare":
		if s.WWW {
			w("    if ($host = www.%s) {\n        return 301 %s://%s$request_uri;\n    }\n", s.Domain, scheme, s.Domain)
		}
	}
	w("    root %s;\n    index index.php index.html index.htm;\n", root)
	w("    client_max_body_size %dm;\n", s.UploadMB)
	// Never follow a symlink to a file of another owner: one account cannot
	// publish another account's files by linking to them.
	w("    disable_symlinks if_not_owner from=$document_root;\n")
	w("    add_header X-Content-Type-Options nosniff always;\n    add_header Referrer-Policy strict-origin-when-cross-origin always;\n")
	for _, r := range s.Redirects {
		w("    location = %s {\n        return %d %s;\n    }\n", r.From, r.Code, r.To)
	}
	// Hidden files (.git, .env, .htaccess) are never served.
	w("    location ~ /\\.(?!well-known/) {\n        deny all;\n    }\n")
	if s.WordPress {
		w("    location ~* ^/wp-config\\.php|/(?:uploads|files)/.*\\.php$ {\n        deny all;\n    }\n")
		if s.BlockXMLRPC {
			w("    location = /xmlrpc.php {\n        deny all;\n    }\n")
		}
		w("    location = /favicon.ico {\n        log_not_found off;\n    }\n    location = /robots.txt {\n        try_files $uri /index.php?$args;\n        log_not_found off;\n    }\n")
	}
	w("    location ~* \\.(?:css|js|mjs|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|eot|mp4|webm|pdf)$ {\n        expires 30d;\n        access_log off;\n        try_files $uri =404;\n    }\n")
	w("    location / {\n        try_files $uri $uri/ /index.php?$args;\n    }\n")
	if s.Cache {
		// Pages are cached only for anonymous GET/HEAD requests without a
		// query; logged-in users, commenters, carts and the admin always
		// see fresh pages. Responses with Set-Cookie are never cached.
		w("    set $hz_nocache 0;\n")
		w("    if ($request_method !~ ^(GET|HEAD)$) {\n        set $hz_nocache 1;\n    }\n")
		w("    if ($query_string != \"\") {\n        set $hz_nocache 1;\n    }\n")
		w("    if ($request_uri ~* \"(/wp-admin/|/wp-login\\.php|/xmlrpc\\.php|/wp-json/|/feed/|sitemap(_index)?\\.xml|/cart/|/checkout/|/my-account/|/basket/)\") {\n        set $hz_nocache 1;\n    }\n")
		w("    if ($http_cookie ~* \"(comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in|woocommerce_items_in_cart|woocommerce_cart_hash|PHPSESSID)\") {\n        set $hz_nocache 1;\n    }\n")
	}
	w("    location ~ \\.php$ {\n        try_files $fastcgi_script_name =404;\n        fastcgi_split_path_info ^(.+\\.php)(/.+)$;\n        include fastcgi_params;\n")
	w("        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n        fastcgi_param PATH_INFO $fastcgi_path_info;\n        fastcgi_param HTTPS $https if_not_empty;\n")
	w("        fastcgi_pass unix:%s;\n        fastcgi_read_timeout 300s;\n", sock)
	if s.Cache {
		w("        fastcgi_cache %s;\n        fastcgi_cache_key \"$scheme$request_method$host$request_uri\";\n", CacheZoneName(s.ID))
		w("        fastcgi_cache_valid 200 301 302 %dm;\n        fastcgi_cache_valid 404 1m;\n", s.CacheMinutes)
		w("        fastcgi_cache_bypass $hz_nocache;\n        fastcgi_no_cache $hz_nocache;\n")
		w("        fastcgi_cache_use_stale error timeout updating http_500 http_503;\n        fastcgi_cache_background_update on;\n        fastcgi_cache_lock on;\n")
		w("        add_header X-Cache $upstream_cache_status always;\n        add_header X-Content-Type-Options nosniff always;\n        add_header Referrer-Policy strict-origin-when-cross-origin always;\n")
		if s.TLS && s.HSTS {
			w("        add_header Strict-Transport-Security \"max-age=31536000\" always;\n")
		}
	}
	w("    }\n")
}

// NginxBase is the http-level configuration HostZit adds once
// (/etc/nginx/conf.d/hostzit.conf): log format, includes, the default
// server that refuses unknown host names.
func NginxBase() string {
	return `# HostZit (generated, do not edit)
log_format hostzit '$remote_addr - [$time_iso8601] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_cache_status';
fastcgi_buffers 16 16k;
fastcgi_buffer_size 32k;
gzip_vary on;
gzip_proxied any;
gzip_types text/plain text/css application/javascript application/json image/svg+xml application/xml text/xml;
include /etc/nginx/zit.d/hostzit/cache/*.conf;
include /etc/nginx/zit.d/hostzit/sites/*/*.conf;
include /etc/nginx/zit.d/emailzit/*.conf;

# Unknown host names: no answer (plain HTTP) and no certificate (HTTPS).
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location ^~ /.well-known/acme-challenge/ {
        alias /var/lib/zit-acme/challenges/;
        default_type text/plain;
        try_files $uri =404;
    }
    location / {
        return 444;
    }
}
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
`
}
