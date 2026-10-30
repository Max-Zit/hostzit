# HostZit — architecture proposal (draft, 2026-10-30)

Status: **proposal, waiting for approval.** Nothing here is built yet. Decisions
shared with EmailZit live in the (local) integration notes and are summarised in
section 11.

HostZit is a self-hosted web hosting control panel in the scope of cPanel/WHM:
an **admin panel** for the server (WHM's role) and a **customer panel** for each
hosting account (cPanel's role). One code base installs either as **shared
hosting** (up to ~500 accounts per server, maximum isolation between them) or as
a **dedicated server** (one account, no sharing, limits off).

Design rule number one: **a hosting server runs other people's code.** Every
account must be treated as compromised, and the panel itself must be built so
that a bug in a web page cannot become root.

## 1. Components

| Component | What it is |
|---|---|
| `hostzit-server` | Go, one binary: admin panel, customer panel, REST API, schedulers (certificates, usage, updates). Runs as the unprivileged `hostzit` user. PostgreSQL for its own data. |
| `hostzit-helper` | Go, root. The only privileged part. Listens on a Unix socket, accepts a short allow-list of typed operations, validates every argument again, renders system configuration from its own templates, applies it atomically and checks it (`nginx -t`, `php-fpm -t`, `named-checkzone`-like checks) before reloading. |
| `hostzit-cage` | Go, small. Starts a process **as an account and inside that account's cage** (section 3): SSH/SFTP sessions, cron jobs, WP-CLI, the file manager worker, Git later. |
| Nginx | Front web server for all sites (HTTP/1.1, HTTP/2, HTTP/3/QUIC), TLS, static files, limits. Debian package. |
| PHP-FPM | Several PHP versions side by side (Debian + the sury.org repository, to confirm). **One FPM master per account and PHP version**, so each account has its own processes, cgroup and mount namespace. |
| PowerDNS Authoritative | Authoritative DNS with the PostgreSQL backend (own `pdns` database, GPLv2, separate program). DNSSEC, NOTIFY/AXFR to secondaries. |
| MariaDB | Customer databases (WordPress). Customer PostgreSQL later. |
| OpenSSH | SFTP/SSH for customers, every session forced through `hostzit-cage`. |
| nftables | Firewall, brute-force bans (sets with timeouts), outbound SMTP block per account. |
| Later | WAF (ModSecurity v3 + OWASP CRS, or Coraza — lab test first), ClamAV, Redis per account, Node.js/Python apps. |

All third-party server software is installed from packages and driven through
its configuration files and command-line tools; no foreign code is copied into
HostZit. Go libraries only with AGPLv3-compatible licenses, listed in
THIRD_PARTY_LICENSES.

Base system: **Debian 13** (Debian 12 also supported while it is in LTS);
Ubuntu 24.04 later if asked for. cgroups v2 and systemd are required.

## 2. Privilege separation

```
browser ──HTTPS──> hostzit-server (user hostzit, no capabilities)
                       │  typed requests over /run/hostzit/helper.sock
                       ▼  (peer uid checked with SO_PEERCRED)
                   hostzit-helper (root, no network, systemd-hardened)
                       │  renders configs from its own templates
                       ▼
          users/slices/quotas · nginx · php-fpm · pdns · mariadb · nftables
```

- **Helper over a Unix socket instead of request.json + path unit** (what
  BackupZit/WatchZit/PassZit use). A hosting panel makes hundreds of small
  privileged changes, often several per click; a socket with one request per
  call is faster and simpler to audit. Peer credentials are checked on every
  connection: only uid `hostzit` (and root for the CLI) may talk to it.
- **Allow-list of operations** (about 40, e.g. `account.create`,
  `account.suspend`, `account.limits`, `site.apply`, `php.pool`, `quota.set`,
  `cert.install`, `dns.zone.apply`, `db.create`, `db.user`, `ban.add`,
  `cage.exec`). Every argument has a strict type: account names
  `^[a-z][a-z0-9]{2,15}$`, domains normalised with IDNA and checked as LDH
  labels, paths resolved **inside** the account's home with `openat2(RESOLVE_BENEATH)`,
  numbers with ranges. Unknown fields are an error.
- **No customer text ever reaches a config file or a shell.** The helper does
  not receive config text from the panel: it receives structured values and
  renders the files itself from templates that escape and re-validate.
  Programs are started with argument lists, never through a shell. Custom
  nginx/PHP directives from customers are not allowed; admins may add
  per-site snippets (marked as admin-only, audited).
- Every helper call carries the panel's request id and user; the helper writes
  its own log and the panel writes the hash-chained audit entry.
- If the panel process is taken over, the attacker gets only what the panel
  can ask for — not arbitrary root commands, and not the files of accounts
  (those are only reachable through `cage.exec` workers that run as the
  account and see only that account).

## 3. Isolation between accounts

Layers, all on by default in shared mode:

1. **Linux user and group per account** (uids from 1 000 000; EmailZit mail uses 2 000 000+),
   home `/home/<account>` 0711, `public_html` and site roots 0750 group
   `hostzit-web` (nginx reads static files; other accounts cannot). PHP and
   all tools run as the account user, so `wp-config.php` is 0600 and nginx
   never needs to read it.
2. **systemd slice per account** (`hostzit-a-<account>.slice`) — cgroups v2
   limits from the package: CPU (`CPUQuota`), memory (`MemoryHigh` +
   `MemoryMax`, no swap storm), IO (`IOWeight`, optional read/write
   bandwidth), processes (`TasksMax`). Everything the account runs — PHP-FPM,
   cron, SSH, WP-CLI, the file manager — lands in this slice, so limits and
   usage graphs cover all of it.
3. **Private mount namespace ("cage", like CloudLinux CageFS)**: the system is
   read-only; `/home` contains only the account's own home; private `/tmp` and
   `/var/tmp`; minimal `/dev`; `/proc` mounted with `hidepid=invisible`, so
   processes of others are invisible; no other accounts' PHP sockets or
   MariaDB data visible. For PHP-FPM this is done by systemd unit sandboxing
   (`ProtectSystem=strict`, `TemporaryFileSystem=/home`, `BindPaths=`,
   `PrivateTmp`, `ProtectProc=invisible`, `NoNewPrivileges`, `RestrictSUIDSGID`,
   `SystemCallFilter=@system-service`, …); for SSH and cron the same set is
   applied by `hostzit-cage` through `systemd-run` into the account's slice.
   One mechanism for everything, maintained by systemd.
4. **Disk quotas** (user quotas on the `/home` file system, ext4 or XFS) for
   files; database size counted from MariaDB and added to the account's usage
   (like cPanel); inode limits.
5. **Network**: outbound SMTP (25/465/587) blocked for account processes
   except through HostZit's sendmail (rate-limited per account, relays to
   EmailZit or a smarthost) — the classic spam-from-a-hacked-WordPress
   problem; optional egress allow-list; nginx `limit_req` per site.
6. **Web server**: nginx `disable_symlinks if_not_owner` (symlink attacks
   across accounts), per-account PHP-FPM socket 0660 `account:hostzit-web`,
   no PHP execution in `wp-content/uploads`, hidden dot files, per-site logs.
7. **PHP**: `open_basedir` to the account (defence in depth inside the cage),
   sensible `disable_functions`, sessions and uploads in the account's private
   tmp, per-site `memory_limit`/upload size within the package limits.
8. **Databases**: per-account MariaDB users with grants only on
   `<account>_*` databases, `max_user_connections`, no FILE/SUPER/PROCESS,
   connection only through the local socket by default; remote access per
   user and IP only when the package allows it.
9. **Kernel/system**: `fs.protected_*`, `kernel.yama.ptrace_scope=1`,
   `kernel.dmesg_restrict`, no compilers/tools for accounts beyond what is
   needed (configurable), hardened SSH.
10. **Later, optional:** a container per account (systemd-nspawn/LXC) for the
    highest tier, and a VM per account only as "dedicated".

**Isolation is tested, not assumed:** an `isolation` test suite runs on a real
server as account A and tries to read, write, list, signal and connect to
account B (files, `/proc`, PHP socket, MariaDB, `/tmp`, symlink through nginx,
hard links, cron, SSH port forwarding to B's FPM). Every release runs it on
a lab VM.

**Dedicated mode** (`install --mode dedicated`): the same layers, one account,
limits switched off, no "other customers" pages; the admin can also be the
customer. Switching later from dedicated to shared is possible.

**Cost of one FPM master per account**: about 5–10 MB each plus workers on
demand (`pm=ondemand`). 500 accounts ≈ 3–5 GB just for masters; to be measured
in the lab with 100–200 test accounts before 0.1 is final. The alternative
(one master with 500 pools) is cheaper but cannot give per-account cgroups or
mount namespaces, so it is not proposed for shared mode.

## 4. Panels and look

Same look as BackupZit/WatchZit/PassZit: dark sidebar #0f172a, indigo
#4f46e5/#818cf8, cards, light/dark with the moon button, Inter/system font,
logo variant B. Server-rendered `html/template` + small own JavaScript (no
frameworks), CSP without inline scripts or styles, works at 375 px. 14
languages (en de fr es it pt nl pl cs sr tr ru zh ja) from catalogs; built-in
user guide (en + sr first, the rest falls back to English, like PassZit).

- **Admin panel** on its own listener (default `:8442`, IP allow-list,
  WHM's 2087): server overview, accounts, packages, DNS servers and templates,
  PHP versions, services, security, updates, backups, audit, settings.
- **Customer panel** (default `:8443` and `https://panel.<server name>/` on
  443, cPanel's 2083): sites, domains, DNS, databases, files, WordPress, cron,
  SSH/SFTP keys, logs and statistics, usage, security, account settings.
- Admins can open a customer's panel ("log in as", audited, banner shown).
- Users inside an account (e.g. a developer with access only to files and one
  site) — later, like cPanel's "manage team".

Security of the panels, as in the other products: HTTPS only, argon2id,
TOTP 2FA with recovery codes (WebAuthn as in PassZit), 2FA mandatory for
admins, roles (admin, operator read-only/support), sessions with idle
timeout and a device list, CSRF via Origin/Sec-Fetch-Site, Secure/HttpOnly/
SameSite cookies, login rate limits and lockouts with `--unblock-ip`, IP
allow-lists, hash-chained audit log, secrets encrypted at rest with the
server key, LDAP/OIDC/SAML for admins, four-eyes approval for dangerous admin
actions (terminate account, change server settings), signed self-update with
`testing`/`official` channels, console backup/restore, appliance images.

## 5. Websites

- Site = domain (+ aliases) → document root inside the account; nginx server
  block and PHP version per site; redirects (301/302, www/non-www, HTTPS),
  custom error pages, IP allow/deny, hotlink protection, password-protected
  directories, headers (HSTS, security headers presets), gzip/brotli.
- **Certificates**: own ACME client in Go (`golang.org/x/crypto/acme`, as in
  BackupZit's console certificates), HTTP-01 for normal names and **DNS-01
  through our own PowerDNS for wildcards**; renewal by the server with ARI
  hints and rate-limit awareness (batching for 500 accounts); upload of own
  certificates; automatic HTTPS for every new site.
- **WordPress `.htaccess`**: nginx does not read `.htaccess`. We generate
  correct WordPress rules (permalinks, wp-config/xmlrpc protection, uploads)
  and recognise the common caching/security plugins. If customers need
  `.htaccess` for other apps, the option is "Apache behind nginx" per site
  later — **question for Stefan** (cPanel uses Apache; Plesk uses nginx +
  optional Apache).
- Staging and clone (WordPress-aware), suspended-site page, maintenance page.

## 6. WordPress toolkit (first application)

Uses WP-CLI (GPLv2, separate program) run through `hostzit-cage` as the
account; WordPress itself is downloaded from wordpress.org at install time.

- Install (version, language, admin user, sane defaults), detect existing
  installs (also after cPanel import).
- One-click login to wp-admin (one-time token via a small mu-plugin).
- Updates: core, plugins, themes; policies (security only / all / manual)
  per site; **snapshot (files + DB) before each update and one-click
  rollback**; schedule and notifications.
- Hardening checklist with one click: file permissions, `DISALLOW_FILE_EDIT`,
  no PHP in uploads, xmlrpc off, security keys rotation, admin user name,
  debug off, directory listing off, version hiding.
- Staging: clone to `staging.<domain>` (files + DB + search-replace), push
  back to live (all or DB only/files only), clone between sites.
- Health: vulnerable plugins/themes (free vulnerability feed, license to
  check), outdated PHP, big tables, cron status.
- Performance: **page cache per site** (nginx FastCGI cache, on/off, lifetime, "Clear cache" button, bypass for logged-in users, cart/checkout, POST and query strings; purge after updates), Redis object
  cache per account (later).

## 7. DNS

- PowerDNS Authoritative, zones in its PostgreSQL backend written only by the
  helper (`dns.zone.apply` with validated records).
- Zone created automatically for every domain an account adds (template:
  SOA, NS, A/AAAA for the site and `www`, CAA for Let's Encrypt, mail records
  from EmailZit when installed — section 11); customer editor for A, AAAA,
  CNAME, MX, TXT, SRV, CAA, NS (delegation), TLSA, HTTPS/SVCB; DNSSEC with
  one click (KSK/ZSK in PowerDNS, DS shown to put at the registrar).
- Nameservers: `ns1/ns2.<provider domain>`; second nameserver = a second
  HostZit server or a "DNS only" install, kept in sync with NOTIFY/AXFR
  (cPanel's DNS cluster in simple form). Domain ownership check before a zone
  for a domain that exists elsewhere on the server is accepted.

## 8. Billing REST API

Under `/api/v1`, Bearer tokens with scopes, created in the admin panel (only
the hash is stored, optional expiry and IP allow-list). Conventions shared
with EmailZit (section 11).

- `POST /customers` (uuid, external id, username, domain, package, contact e-mail),
  `GET /customers`, `GET /customers/{id}`, `POST /customers/{id}/suspend`
  (reason), `/unsuspend`, `/terminate` (data kept N days), `PUT /customers/{id}/package`,
  `PATCH /customers/{id}` (password, contact),
  `GET /customers/{id}/usage` (disk, inodes, bandwidth, CPU, memory, DBs,
  sites), `POST /customers/{id}/sso` (one-time single sign-on URL, 60 s).
- `GET/POST/PATCH/DELETE /packages`, `GET /server/status`.
- Slow work (creating an account, terminating) returns `202` with a
  job id; `GET /jobs/{id}` and optional signed webhook to the portal.
- `Idempotency-Key` on POST, so a retry from the portal never makes two
  accounts.

## 9. cPanel/WHM comparison (checklist)

| cPanel/WHM area | HostZit plan |
|---|---|
| WHM: create/modify/suspend/terminate accounts, packages, feature lists | 0.1 (packages carry limits and feature switches) |
| WHM: reseller accounts | **Not planned** (Stefan's decision) |
| WHM: DNS functions, DNS cluster, zone templates | 0.2; cluster = secondary NS later |
| WHM: SSL/TLS, AutoSSL | 0.2 (own ACME, wildcard via own DNS) |
| WHM: MultiPHP manager, PHP-FPM, EasyApache | 0.4 (several PHP versions, extensions by package) |
| WHM: service manager, server status, process manager | 0.1 basic, 0.4 more |
| WHM: security center (cPHulk, ModSecurity, 2FA, shell fork bomb protection, compiler access) | 2FA 0.1; brute force, WAF, compilers 0.5; fork bombs → `TasksMax` 0.1 |
| WHM: backup configuration, transfer tool, restore | 0.7 (own backups + BackupZit; cPanel import) |
| WHM: CageFS/CloudLinux LVE (third party) | **built in**: cage + slices from 0.1 |
| WHM: update preferences, tiers | 0.8 (signed self-update, testing/official) |
| cPanel: domains, subdomains, aliases, redirects, zone editor | 0.2 |
| cPanel: file manager, disk usage, directory privacy, FTP | 0.4 (SFTP instead of FTP; FTP only if asked) |
| cPanel: MySQL databases, phpMyAdmin, remote MySQL | 0.3 (phpMyAdmin or Adminer with single sign-on — to choose) |
| cPanel: SSL/TLS status, SSH access, cron jobs | 0.2 / 0.4 |
| cPanel: metrics (visitors, errors, bandwidth, AWStats, raw logs, resource usage) | 0.4 (own log parser, usage graphs from cgroups) |
| cPanel: email accounts, forwarders, spam filters, webmail | **EmailZit** |
| cPanel: WordPress Toolkit / WP Toolkit (Plesk) | 0.3 basic, 0.6 staging/snapshots |
| cPanel: Softaculous, Git version control, Application Manager (Node/Python/Ruby) | later (Git deploy, Node.js/Python apps) |
| cPanel: ImunifyAV/360 (third party) | ClamAV + own WordPress checks 0.5 |
| cPanel: WHMCS integration (API) | REST API from 0.1 |

## 10. Version order (proposal)

| Version | Content |
|---|---|
| 0.1 | Foundation: Go server + PostgreSQL, admin and customer panel with sign-in/2FA/roles/audit, root helper over the socket, `install.sh` for Debian 13, accounts (user, slice, cage, quota) and packages, one website per domain with nginx + PHP-FPM (one PHP version), SFTP through the cage, REST API for accounts (create/suspend/unsuspend/terminate/package/login link), isolation test suite on a lab VM, CI + security workflows. |
| 0.2 | DNS (PowerDNS, zones, editor, templates, DNSSEC), subdomains/aliases/redirects, Let's Encrypt incl. wildcard via DNS-01, HTTP/2/3, DNS interface for EmailZit. |
| 0.3 | Databases (MariaDB, users, grants, phpMyAdmin/Adminer sign-in), WordPress toolkit 1 (install, detect, wp-admin login, updates, hardening). |
| 0.4 | File manager, cron jobs, SSH keys + caged shell, logs and statistics, usage graphs, several PHP versions + php.ini per site, notifications (quota, certificates, updates). |
| 0.5 | Security: brute-force blocking (wp-login, xmlrpc, SSH, panel) with nftables, WAF + OWASP CRS, ClamAV scans, rate-limited sendmail and outbound SMTP block, IP/hotlink rules, password-protected directories. |
| 0.6 | WordPress toolkit 2: staging, clone, push, snapshots + rollback, update policies, vulnerability checks, FastCGI cache. |
| 0.7 | cPanel backup import (cpmove: home, databases, DNS zones, SSL, cron, addon/sub domains; mail → EmailZit), own account backup/restore, BackupZit integration, console backup/restore. |
| 0.8 | Operations: signed self-update with channels, appliance ISO/OVA/qcow2/VHDX, OS updates, LDAP/SSO for admins, four-eyes approval, secondary DNS server, WatchZit integration, guide in 14 languages. |
| later | Node.js/Python apps, Git deployment, Redis, customer PostgreSQL, container per account, several servers under one admin panel. |

## 11. Shared with EmailZit (summary)

- One customer in both products, linked by a shared `customer_id` (UUID) that
  the portal (or the first product) assigns; same package concept.
- One sign-in when both are installed: HostZit is the OpenID Connect provider
  for customers and admins, EmailZit an OIDC client; 2FA once. Standalone,
  each product signs in on its own.
- Same look, a product switcher in the header, same REST conventions
  (`/api/v1`, Bearer tokens `hzt_`/`ezt_`, JSON errors, cursor pagination, idempotency keys,
  jobs).
- DNS: EmailZit publishes its records (MX, SPF, DKIM, DMARC, autoconfig/
  autodiscover, MTA-STS, TLS-RPT) into HostZit's zones as **managed record
  sets** (`PUT /api/v1/dns/zones/{zone}/owned/emailzit`); customers see them as "managed by EmailZit".
- On one server: one nginx (HostZit owns nginx.conf, each product its drop-in dir `/etc/nginx/zit.d/<product>/`), ports HostZit 8443/8442 and EmailZit 8444, one PostgreSQL cluster with
  separate databases and roles, own ACME client per product with a shared challenge directory,
  PHP mail through `emailzit-sendmail` (socket bind-mounted into the cages) when EmailZit is installed, else `hostzit-sendmail`; web uids 1 000 000+, mail uids 2 000 000+.

## 12. Tests and tools

Unit tests (helper validation and templates with hostile input, config
renderers, API), `go vet`, staticcheck, govulncheck, gosec in CI; Semgrep,
Trivy, Gitleaks, OWASP ZAP (both panels, authenticated) and OpenVAS from the
lab scanner; isolation suite and real WordPress sites on lab VMs (ESXi
`hz-*`); panels checked in the preview at desktop and 375 px, light and dark.
