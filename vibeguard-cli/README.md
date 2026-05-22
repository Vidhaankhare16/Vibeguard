# vibeguard

> Zero-trust vulnerability scanner for vibe-coded (AI-generated) applications.

```bash
npx @vidhaankhare/vibeguard scan .
```

No account. No config. One command.

---

## Install

```bash
# Use via npx (no install needed)
npx @vidhaankhare/vibeguard scan .

# Install globally
npm install -g @vidhaankhare/vibeguard
vibeguard scan .
```

## Usage

```bash
vibeguard scan [path] [options]

Options:
  -y, --yes   Skip interactive prompts (non-interactive / CI mode)
  -v          Print version
  -h          Help
```

**Examples:**

```bash
vibeguard scan .                  # Scan current directory
vibeguard scan ./my-app           # Scan a specific path
vibeguard scan . --yes            # Non-interactive (for CI/CD)
npx @vidhaankhare/vibeguard scan . --yes        # One-line CI command
```

## What it checks

| Phase | Description |
|---|---|
| Supply-Chain Audit | Hallucinated/slopsquatted npm packages |
| Access Control Audit | Missing auth middleware, unauthenticated admin endpoints |
| Prompt Injection Audit | Raw user input flowing into LLM system prompts |
| Secrets & Defaults | Hardcoded API keys, wildcard CORS |

## Output

Generates two report files in the scanned directory:

- `vibeguard-report.json` — Machine-readable (for CI/CD)
- `vibeguard-report.md` — Human-readable with CVSS scores and fix instructions

## License

MIT © 2026 VibeGuard Security
