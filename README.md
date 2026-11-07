<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/hostzit-logo-on-dark.svg">
    <img src="brand/hostzit-logo-on-light.svg" alt="HostZit" height="64">
  </picture>
</p>

# HostZit

[![Latest release](https://img.shields.io/github/v/release/Max-Zit/hostzit?label=release)](https://github.com/Max-Zit/hostzit/releases/latest)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue)](LICENSE)
[![CI](https://github.com/Max-Zit/hostzit/actions/workflows/ci.yml/badge.svg)](https://github.com/Max-Zit/hostzit/actions/workflows/ci.yml)
[![Security scan](https://github.com/Max-Zit/hostzit/actions/workflows/security.yml/badge.svg)](https://github.com/Max-Zit/hostzit/actions/workflows/security.yml)

**Free, open-source, self-hosted web hosting control panel** — for shared hosting with strong isolation between accounts, or for a single dedicated server.

> **Status:** under active development; releases with VM images are on [Releases](https://github.com/Max-Zit/hostzit/releases) and new versions come out often. Development happens on the `develop` branch. News in [Discussions](https://github.com/Max-Zit/hostzit/discussions).

## What it does

- **Two panels:** the admin panel (customers, packages, websites, DNS, server, updates, audit log) and the customer panel (websites, domains and DNS, WordPress, databases, files, SFTP/SSH, scheduled jobs, backups, security, usage). The interface is in 14 languages; the user guide is in English and Serbian.
- **Isolation between accounts:** every account is its own Linux user with its own PHP processes (no root), its own CPU/memory/disk speed/process limits (cgroups v2), disk quotas and a private view of the file system for PHP, cron jobs, SSH and SFTP: other accounts' files, processes and databases are invisible. An isolation test suite checks this on real servers.
- **Resource usage:** a page of all accounts with CPU, memory, disk speed and processes (average, peak and how often the package limits held an account back); customers see their own limit hits.
- **Websites:** nginx with PHP-FPM, PHP 5.6 to 8.6 chosen per website, PHP extensions and php.ini settings per account, free automatic HTTPS (Let's Encrypt, renew on demand), HTTP/2 and HTTP/3, redirects, aliases, a **page cache** per site with one-click clearing, IP rules, hotlink protection, folders with a password, login rate limits, **Redis** per account, visitor statistics per site (GoAccess).
- **Applications and Git:** Node.js and Python applications that run as the account within its limits; Git deployment by a push over SSH or by a webhook from GitHub, GitLab, Gitea and others.
- **WordPress toolkit:** install in a minute, one-click sign-in to wp-admin, updates with a snapshot before each one and one-click restore, nightly automatic updates, hardening, **staging copies** and push to live.
- **Domains and DNS:** authoritative DNS (PowerDNS) with an editor and DNSSEC, secondary name servers (AXFR/NOTIFY) and a DNS-only second name server.
- **Databases:** MariaDB databases and users, and a database manager in the customer panel (tables, rows, SQL, export).
- **Mail from websites** goes through a queue with an hourly limit per package; accounts cannot send mail directly. Mail hosting is [EmailZit](https://github.com/Max-Zit/emailzit).
- **Migration:** import of full cPanel backups (websites, databases with their passwords, DNS zones, cron jobs); moving accounts to another HostZit server.
- **Backups:** nightly incremental, encrypted restore points of every account (restic) to a local folder, SFTP or S3, with daily/weekly/monthly retention; customers restore single files, databases, DNS records and cron jobs. Nightly encrypted backups of the panel itself.
- **Protection against attacks:** web application firewall (ModSecurity + OWASP CRS) with per-site tuning, ClamAV malware scans with quarantine and a WordPress file check against the official checksums, brute-force protection (fail2ban) with **Unblock**, and blocking by country for the panels, SSH/SFTP and websites.
- **Billing:** REST API for customers, packages, suspension, usage and single sign-on links.
- **Server:** operating system and PHP updates from the panel, a Let's Encrypt certificate for the panels, notifications (limits hit, stopped services, disk almost full, waiting security updates, failed backups).
- **Security of the panel:** root work only through a small helper with a strict list of operations, two-factor sign-in, company sign-in for admins (OpenID Connect), four-eyes approval for deleting customers and packages, roles, hash-chained audit log, signed self-updates.

## Install

| Way | Best for |
|---|---|
| **VM image** — [OVA](https://github.com/Max-Zit/hostzit/releases/latest/download/hostzit-appliance.ova) (VMware, VirtualBox), [qcow2](https://github.com/Max-Zit/hostzit/releases/latest/download/hostzit-appliance.qcow2) (Proxmox/KVM), [VHDX](https://github.com/Max-Zit/hostzit/releases/latest/download/hostzit-appliance-vhdx.zip) (Hyper-V) | import and start; Debian with HostZit ready |
| **Appliance ISO** — [hostzit-appliance.iso](https://github.com/Max-Zit/hostzit/releases/latest/download/hostzit-appliance.iso) | a new VM or a physical server |
| **Install script** | an existing Debian 12 or 13 server (amd64, arm64) |

```sh
curl -fsSL https://github.com/Max-Zit/hostzit/releases/latest/download/install.sh | sudo bash
```

The installer sets up nginx, PHP-FPM, MariaDB, PostgreSQL, PowerDNS (unless DNS is switched off with `--no-dns`) and the HostZit services, checks the signature of the release and prints the address of the admin panel with the one-time setup token. The VM images show the panel addresses and the setup token on the VM screen after the first start; sign in there as `hzadmin` (first password `hostzit`, which must be changed; SSH password sign-in for `hzadmin` stays off until then) for network, server name and time zone.

HostZit is made by [MaxZit](https://maxzit.com), like [BackupZit](https://github.com/Max-Zit/backupzit), [RMMZit](https://github.com/Max-Zit/rmmzit), [WatchZit](https://github.com/Max-Zit/watchzit) and [PassZit](https://github.com/Max-Zit/passzit).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Paid support will be offered by MaxZit.
