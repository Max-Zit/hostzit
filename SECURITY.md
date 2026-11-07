# Security policy

## Supported versions

HostZit is in development; security fixes will be released for the newest version once releases start.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Open the [Security tab](https://github.com/Max-Zit/hostzit/security) of this repository.
2. Click **Report a vulnerability** and describe the problem, the affected version and how to reproduce it.

We confirm reports within a few working days, fix confirmed problems in a new release and credit the reporter in the release notes unless they prefer otherwise.

## How HostZit is tested

**On every change** (GitHub Actions, one workflow per push):

- build for amd64 and arm64, gofmt, `go vet` and the full test suite (against an embedded PostgreSQL), and the whole suite again with the Go **race detector**;
- **fuzzing** of every parser that reads outside data — cPanel and HostZit archives (account import and moves between servers: metadata, MySQL grants, BIND zones, manifests), DNS records, the generated web server, cron and PHP configuration, Git repositories and addresses, file manager paths and uploads, uploaded panel backups and database dumps, restore point paths, the ModSecurity audit log, fail2ban, MariaDB and GoAccess output, DNS answers, network allow-lists, sign-in redirects and REST API request bodies;
- staticcheck, gosec, govulncheck, Gitleaks, CodeQL, Dependabot, secret scanning with push protection and the [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Max-Zit/hostzit); the security checks run again every week for new CVEs.

**Before every release**, in a test lab:

- source code: Semgrep, Trivy and Gitleaks;
- the running server: an authenticated OWASP ZAP scan of a freshly installed appliance — the admin panel and the customer panel — a crawl of every page as administrator, operator, read-only user and customer, and probes that every write or admin route refuses the roles that may not use it and that customers cannot reach each other's sites, databases, files, backups or DNS zones;
- the appliance image: Trivy over its operating-system packages, a Lynis hardening audit, testssl.sh on every public TLS port (admin panel 8442, customer panel 8443, websites 443), an SSH audit of port 22 (SSH/SFTP) and Nuclei; OpenVAS / Greenbone for larger releases;
- an end-to-end test on real servers (install, websites, PHP, databases, DNS with secondaries, backups and restore points, moves between servers, notifications, updates), and the appliance images imported on Proxmox, VMware ESXi and Hyper-V.

Findings are fixed before the release; accepted risks are documented in the release notes.
