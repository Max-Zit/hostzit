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

## Install

| Way | Best for |
|---|---|
| **VM image** — [OVA](https://github.com/Max-Zit/hostzit/releases/latest/download/hostzit-appliance.ova) (VMware, VirtualBox), [qcow2](https://github.com/Max-Zit/hostzit/releases/latest/download/hostzit-appliance.qcow2) (Proxmox/KVM), [VHDX](https://github.com/Max-Zit/hostzit/releases/latest/download/hostzit-appliance-vhdx.zip) (Hyper-V) | import and start; Debian with HostZit ready |
| **Appliance ISO** — [hostzit-appliance.iso](https://github.com/Max-Zit/hostzit/releases/latest/download/hostzit-appliance.iso) | a new VM or a physical server |
| **Install script** | an existing Debian 12 or 13 server (amd64, arm64) |

```sh
curl -fsSL https://github.com/Max-Zit/hostzit/releases/latest/download/install.sh | sudo bash
```

<<<<<<< HEAD
The installer sets up nginx, PHP-FPM, MariaDB, PowerDNS, PostgreSQL and the HostZit services, checks the signature of the release and prints the address of the admin panel with the one-time setup token. The VM images show the panel addresses and the setup token on the VM screen after the first start; sign in there as `hzadmin` (first password `hostzit`, which must be changed; SSH password sign-in for `hzadmin` stays off until then) for network, server name and time zone.
=======
The installer sets up nginx, PHP-FPM, MariaDB, PowerDNS, PostgreSQL and the HostZit services, checks the signature of the release and prints the address of the admin panel with the one-time setup token. The VM images show the panel addresses and the setup token on the VM screen after the first start; sign in there as `hzadmin` (first password `hostzit`, which must be changed) for network, server name and time zone.
>>>>>>> origin/main

HostZit is made by [MaxZit](https://maxzit.com), like [BackupZit](https://github.com/Max-Zit/backupzit), [RMMZit](https://github.com/Max-Zit/rmmzit), [WatchZit](https://github.com/Max-Zit/watchzit) and [PassZit](https://github.com/Max-Zit/passzit).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Paid support will be offered by MaxZit.
