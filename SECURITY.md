# Security policy

## Supported versions

HostZit is in development; security fixes will be released for the newest version once releases start.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Open the [Security tab](https://github.com/Max-Zit/hostzit/security) of this repository.
2. Click **Report a vulnerability** and describe the problem, the affected version and how to reproduce it.

We confirm reports within a few working days, fix confirmed problems in a new release and credit the reporter in the release notes unless they prefer otherwise.

## How HostZit is tested

On every change: GitHub Actions (go vet and the tests), CodeQL, govulncheck, staticcheck, Dependabot, secret scanning with push protection and OpenSSF Scorecard. Before releases, in a test lab: gosec, Semgrep, Trivy, Gitleaks, an OWASP ZAP scan of the running console and end-to-end tests against real devices.
