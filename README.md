# VibeGuard

**Zero-trust vulnerability scanner and security auditor custom-built for vibe-coded (AI-generated) applications.**

Unlike standard security tools that assume modular software architecture and experienced developer workflows, VibeGuard is designed to hunt down the specific blind spots, insecure defaults, logical slip-ups, and AI supply-chain vulnerabilities common to AI-authored code.

---

## Quick Start

```bash
npx @vidhaankhare/vibeguard scan .
```

No account. No config. No setup. Point it at any project directory.

---

## Project Structure

```
vibeguard-cli/   ← The CLI tool (npm package: vibeguard)
website/         ← Marketing landing page (open index.html in browser)
```

---

## CLI Usage

```bash
# Run without installing (via npx)
npx @vidhaankhare/vibeguard scan .

# Install globally
npm install -g @vidhaankhare/vibeguard
vibeguard scan .

# Scan a specific directory
vibeguard scan ./my-app

# Non-interactive mode (for CI/CD)
vibeguard scan . --yes

# Show help
vibeguard --help
vibeguard scan --help
```

---

## What VibeGuard Checks

VibeGuard runs 4 phases covering 10 vulnerability layers:

| Phase | What it checks |
|---|---|
| **Phase 1** — Supply-Chain & Hallucination Audit | Hallucinated/slopsquatted npm packages, newly registered dependencies |
| **Phase 2** — Static Call-Graph & Access Control | AST-based route mapping, missing auth middleware, unauthenticated endpoints |
| **Phase 3** — AI Prompt Injection Boundary Audit | Raw user input in LLM system prompts, missing sanitization |
| **Phase 4** — Secrets & Default Config Audit | Hardcoded API keys, wildcard CORS, insecure defaults |

**10 Vulnerability Layers:** AI-specific patterns · Authorization/Access Control · Injection · Secrets · Auth/Sessions · Data Exposure · Security Misconfiguration · Client-Side · Infrastructure · Supply Chain

---

## Output

VibeGuard exports two report files after every scan:

- **`vibeguard-report.json`** — Machine-readable, suitable for CI/CD pipelines
- **`vibeguard-report.md`** — Human-readable markdown with CVSS scores and remediation steps

---

## Running the CLI Locally

```bash
cd vibeguard-cli
npm install
node bin/index.js scan .
```

Or link it globally:
```bash
cd vibeguard-cli
npm link
vibeguard scan .
```

---

## The Landing Page

Open `website/index.html` directly in any browser — no build step required.

---

## Publishing to npm

When ready to publish the CLI as a public npm package:

```bash
cd vibeguard-cli
npm login
npm publish --access public
```

After publishing, anyone can run `npx @vidhaankhare/vibeguard scan .` instantly.

---

## The Problem VibeGuard Solves

- AI-generated code contains **2.74× more security vulnerabilities** than human-written code (CodeRabbit, 2025)
- **45%** of AI-generated applications contain exploitable OWASP vulnerabilities (Veracode, 2025)
- **5,000** vibe-coded apps were found with virtually no security or authentication (Dor Zvi, 2026)
- **322%** more privilege escalation paths in AI code than human-written code (Apiiro, 2025)

There is no purpose-built tool for this era. VibeGuard fills that gap.

---

MIT Licensed · © 2026 VibeGuard Security
