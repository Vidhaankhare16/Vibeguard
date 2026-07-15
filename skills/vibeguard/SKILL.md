---
name: vibeguard
description: Run a VibeGuard zero-trust security audit on a codebase and summarize the findings. Use when the user asks to security-scan, audit, or "vibe-check" a project, when reviewing AI-generated code for vulnerabilities, or after generating a substantial amount of new code that should be checked before shipping.
metadata: {"openclaw": {"emoji": "🛡️", "requires": {"bins": ["npx"]}, "install": [{"id": "node", "kind": "info", "label": "Requires Node.js >= 16 (npx ships with npm)"}]}}
---

# VibeGuard Security Audit

VibeGuard is a zero-trust vulnerability scanner built specifically for vibe-coded
(AI-generated) applications. It hunts the failure modes AI code is prone to:
hallucinated/slopsquatted dependencies, unauthenticated mutation endpoints, raw user
input interpolated into LLM prompts, hardcoded secrets, and wildcard CORS.

## Running a scan

1. Identify the target directory. Default to the current workspace/project root unless
   the user names a path. Never scan `/` or a home directory root.
2. Run the scan non-interactively:

   ```bash
   npx -y @vidhaankhare/vibeguard scan <target-dir> --yes
   ```

3. The scan writes two report files **into the target directory**:
   - `vibeguard-report.json` — machine-readable: `securityScore` (0–100),
     `vulnerabilityCounts` by severity (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), and a
     `vulnerabilities` array with `id`, `title`, `severity`, `category`, `file`,
     `line`, `description`, `code`, and `fix` for each finding.
   - `vibeguard-report.md` — human-readable report with remediation steps.

## Reporting results back

Read `vibeguard-report.json` (prefer it over parsing terminal output) and reply with:

- The **security score** out of 100 and a one-line verdict.
- Findings grouped by severity, worst first — for each: title, `file:line`, and the
  suggested fix in one sentence. On chat surfaces (WhatsApp/Telegram/Discord) keep it
  to the top 5 findings and offer the full report on request.
- If the user asks for the full report, send `vibeguard-report.md` as a file.

## Fix loop (optional)

If the user asks you to fix the findings: apply each `fix` from the JSON report,
re-run the scan, and report the score delta (e.g. "32 → 78 after patching 4 issues").
Never auto-commit fixes — show the diff and let the user decide.

## Cleanup

The report files are generated artifacts. Ask before committing them; suggest adding
`vibeguard-report.*` to `.gitignore` for repos that scan regularly.
