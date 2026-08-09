---
name: vibeguard
description: Run a VibeGuard security audit on a codebase and summarize the findings. Use when the user asks to security-scan, audit, or "vibe-check" a project, when reviewing AI-generated code for vulnerabilities, or after generating a substantial amount of new code that should be checked before shipping.
metadata: {"openclaw": {"emoji": "🛡️", "requires": {"bins": ["npx"]}, "install": [{"id": "node", "kind": "info", "label": "Requires Node.js >= 18 (npx ships with npm)"}]}}
---

# VibeGuard Security Audit

VibeGuard scans a folder for vulnerabilities and writes a Markdown report into that
folder. It combines a deterministic pattern engine with a Gemini review pass, and
targets the failure modes AI-generated code is prone to: unauthenticated mutation
endpoints, hardcoded secrets, secrets leaked into client bundles, prompt injection,
SQL/shell injection, and insecure defaults.

## Running a scan

1. Identify the target directory. Default to the current workspace/project root unless
   the user names a path. Never scan `/` or a home directory root — VibeGuard refuses
   these anyway.
2. Run the scan:

   ```bash
   npx -y @vidhaankhare/vibeguard scan <target-dir> --quiet
   ```

   `--quiet` prints a single summary line; the full data is in the report files.

3. Useful variants:
   - `--no-ai` — pattern engine only. Use when there is no API key, when the user
     wants zero network calls, or when a previous run reported a quota error.
   - `--fail-on high` — non-zero exit if anything high or critical is found.
   - `-o <name>.md` — custom report filename.

## If the AI pass is unavailable

VibeGuard never fails the scan when Gemini is unreachable — it completes on the
pattern engine and prints what went wrong. If the output mentions a missing key or
exhausted quota, report that to the user alongside the findings:

- **No API key** → they can add one with `npx -y @vidhaankhare/vibeguard auth <key>`
  (free keys at https://aistudio.google.com/apikey).
- **No credit / quota exhausted** → the key works but the Google Cloud project has no
  generation quota; they need to top up or use a key from another project.
- Suggest `npx -y @vidhaankhare/vibeguard doctor` to diagnose.

Do not ask the user for their API key, and never paste a key into a file in the repo.

## Reading the results

The scan writes two files **into the target directory**:

- `SECURITY-REPORT.md` — the human-readable report.
- `vibeguard-report.json` — machine-readable. Prefer this over parsing terminal output.

JSON shape:

```jsonc
{
  "securityScore": 42,          // 0-100
  "verdict": "DANGEROUS",       // STRONG | FAIR | AT RISK | DANGEROUS | CRITICAL
  "engine": { "ai": true, "model": "gemini-3.6-flash" },
  "vulnerabilityCounts": { "CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 0 },
  "vulnerabilities": [
    {
      "id": "VG-INJ-001", "title": "...", "severity": "CRITICAL",
      "category": "Injection", "cwe": "CWE-89",
      "file": "src/api/users.js", "line": 12,
      "code": "...", "description": "...", "fix": "...",
      "source": "static",       // "static" | "gemini"
      "confidence": "high"      // gemini findings only
    }
  ]
}
```

## Reporting results back

Reply with:

- The **security score** out of 100, the verdict label, and a one-line read on it.
- Findings grouped by severity, worst first — for each: title, `file:line`, and the
  fix in one sentence. On chat surfaces (WhatsApp/Telegram/Discord) keep it to the
  top 5 and offer the full report on request.
- Note when `engine.ai` is `false`, so the user knows only pattern analysis ran.
- Treat `source: "gemini"` findings with `confidence: "low"` as worth verifying
  rather than stating as fact.
- If the user asks for the full report, send `SECURITY-REPORT.md` as a file.

## Fix loop (optional)

If the user asks you to fix the findings: apply each `fix` from the JSON report,
re-run the scan, and report the score delta (e.g. "32 → 78 after patching 4 issues").
Never auto-commit fixes — show the diff and let the user decide.

Any credential named in a finding must be **rotated**, not just deleted — it is
already in git history. Say this explicitly when reporting a secrets finding.

## Cleanup

The report files are generated artifacts. Ask before committing them; suggest adding
`SECURITY-REPORT.md` and `vibeguard-report.json` to `.gitignore` for repos that scan
regularly.
