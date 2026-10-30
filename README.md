<p align="center"><img src="brand/hostzit-logo-on-light.svg" alt="HostZit" height="64"></p>

# HostZit

**Free, open-source, self-hosted web hosting control panel** — a modern alternative to cPanel/WHM for shared hosting with strong isolation between accounts, or for a single dedicated server.

> **Status:** in development. There is no release yet; follow the repository or [Discussions](https://github.com/Max-Zit/hostzit/discussions) for news.

## Planned

- **Two panels:** the server administrator manages packages, accounts, limits and the server; every customer manages their own websites, domains, databases, files and DNS.
- **Isolation between accounts:** every account runs as its own Linux user with its own PHP processes, CPU/memory/disk/process limits and a private view of the file system; SFTP locked to the account.
- **Websites:** Nginx with PHP-FPM, several PHP versions per site, free automatic HTTPS (Let's Encrypt), redirects, staging copies, a WordPress toolkit (install, updates, security, clone).
- **Domains and DNS:** authoritative DNS for customer domains, subdomains, aliases, DNSSEC.
- **Databases:** MariaDB/MySQL and PostgreSQL per account, with users and a web admin tool.
- **Security:** web application firewall, brute-force protection, malware scanning, two-factor sign-in, roles, hash-chained audit log, signed updates.
- **Migration:** import of cPanel backups.
- **Works with the other MaxZit products:** [EmailZit](https://github.com/Max-Zit/emailzit) for mail hosting with one sign-in, [BackupZit](https://github.com/Max-Zit/backupzit) for account backups, [WatchZit](https://github.com/Max-Zit/watchzit) for monitoring; REST API for billing systems.
- **Self-hosted:** Debian package or appliance image, 14 languages.

HostZit is made by [MaxZit](https://maxzit.com), like [BackupZit](https://github.com/Max-Zit/backupzit), [ControlZit](https://github.com/Max-Zit/controlzit), [WatchZit](https://github.com/Max-Zit/watchzit) and [PassZit](https://github.com/Max-Zit/passzit).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE). Paid support will be offered by MaxZit.
