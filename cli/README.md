# ⚡ vibesec

> Extraordinary security audit for AI-generated apps. One command, zero config.

[![npm version](https://img.shields.io/npm/v/vibesec)](https://www.npmjs.com/package/vibesec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Install & run

```bash
npx vibesec scan .
```

Or install globally:

```bash
npm install -g vibesec
vibesec scan .
```

## What it checks (v1.0 — coming soon)

| Layer | Checks |
|---|---|
| 01 | AI-specific vulnerability patterns (slopsquatting, mass assignment, prompt injection) |
| 02 | Authorization & access control (BOLA/IDOR, broken function-level auth) |
| 03 | Injection vulnerabilities (SQL, command, path traversal, SSRF, NoSQL) |
| 04 | Secrets in codebase (500+ secret formats) |
| 05 | Git history secrets (full commit history + dangling objects) |
| 06 | Authentication & session security (JWT flaws, OAuth misconfig) |
| 07 | Data exposure (excessive API responses, sensitive data in transit) |
| 08 | Security misconfiguration (headers, CORS, error handling) |
| 09 | Client-side vulnerabilities (XSS, prototype pollution, clickjacking) |
| 10 | Infrastructure & supply chain (cloud misconfig, dependency confusion) |

## CLI options

```
vibesec scan [path] [options]

Options:
  -o, --output <format>    Output format: terminal | json | html  (default: terminal)
  --no-git                 Skip git history scanning
  --no-deps                Skip dependency verification
  --severity <level>       Minimum severity: critical | high | medium | low  (default: low)
  -v, --version            Print version number
  -h, --help               Display help
```

## Status

This is an early access release. The CLI scaffold is published and installable. The full analysis engine is under active development.

**[Star the repo](https://github.com/vibesec/vibesec)** to get notified when v1.0 ships.

## Website

[vibesec.dev](https://vibesec.dev)

## License

MIT
