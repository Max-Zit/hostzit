<p align="center"><img src="brand/hostzit-logo-on-light.svg" alt="HostZit" height="64"></p>

# HostZit

**Free, open-source, self-hosted web hosting control panel** — a modern alternative to cPanel/WHM for shared hosting with strong isolation between accounts, or for a single dedicated server.

> **Status:** in development on the `develop` branch; there is no release yet. Follow the repository or [Discussions](https://github.com/Max-Zit/hostzit/discussions) for news.

## What it does

- **Two panels:** the admin panel (customers, packages, websites, DNS, server, updates, audit log) and the customer panel (websites, domains and DNS, WordPress, databases, files, SFTP/SSH, scheduled jobs, backups, security, usage).
- **Isolation between accounts:** every account is its own Linux user with its own PHP processes (no root), its own CPU/memory/IO/process limits (cgroups v2), disk quotas and a private view of the file system for PHP, cron jobs, SSH and SFTP: other accounts' files, processes and databases are invisible. An isolation test suite checks this on real servers.
- **Websites:** nginx with PHP-FPM, several PHP versions, free automatic HTTPS (Let's Encrypt), HTTP/2 and HTTP/3, redirects, aliases, a **page cache** per site with one-click clearing, web application firewall (ModSecurity + OWASP CRS), IP rules, hotlink protection, folders with a password, login rate limits.
- **WordPress toolkit:** install in a minute, one-click sign-in to wp-admin, updates with a snapshot before each one and one-click restore, nightly automatic updates, hardening, **staging copies** and push to live.
- **Domains and DNS:** authoritative DNS (PowerDNS) with an editor and DNSSEC.
- **Databases:** MariaDB databases and users.
- **Mail from websites** goes through a queue with an hourly limit per package; accounts cannot send mail directly. Mail hosting is [EmailZit](https://github.com/Max-Zit/emailzit).
- **Migration:** import of full cPanel backups (websites, databases with their passwords, DNS zones, cron jobs).
- **Backups:** account backups with files, databases and settings; nightly encrypted backups of the panel itself.
- **Billing:** REST API for customers, packages, suspension, usage and single sign-on links.
- **Security of the panel:** root work only through a small helper with a strict list of operations, two-factor sign-in, roles, hash-chained audit log, signed self-updates.

## Install (Debian 12 or 13)

```sh
curl -fsSL https://github.com/Max-Zit/hostzit/releases/latest/download/install.sh | sudo bash
```

The installer sets up nginx, PHP-FPM, MariaDB, PowerDNS, PostgreSQL and the HostZit services, checks the signature of the release and prints the address of the admin panel with the one-time setup token.

HostZit is made by [MaxZit](https://maxzit.com), like [BackupZit](https://github.com/Max-Zit/backupzit), [ControlZit](https://github.com/Max-Zit/controlzit), [WatchZit](https://github.com/Max-Zit/watchzit) and [PassZit](https://github.com/Max-Zit/passzit).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Paid support will be offered by MaxZit.
