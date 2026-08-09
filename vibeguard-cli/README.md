# VibeGuard

**Point it at a folder. Get a Markdown security report in that folder.**

VibeGuard combines a deterministic pattern engine with a Gemini review pass to find
the vulnerabilities that AI-generated code actually ships with — unauthenticated
mutation endpoints, hardcoded keys, prompt injection, insecure defaults copied from
tutorials.

```bash
npx @vidhaankhare/vibeguard scan .
```

That writes `SECURITY-REPORT.md` (and `vibeguard-report.json`) into the directory
you scanned.

---

## Setup

VibeGuard runs without any configuration — the pattern engine needs nothing. To
enable the Gemini review pass, add a key once:

```bash
npx @vidhaankhare/vibeguard auth <your-gemini-api-key>
```

Free keys: **https://aistudio.google.com/apikey**

The key is stored in `~/.vibeguard/config.json`, never in your project. VibeGuard
also reads `GEMINI_API_KEY` / `GOOGLE_API_KEY` from the environment or a local
`.env`, and accepts `--key` per-run.

Check everything is wired up:

```bash
npx @vidhaankhare/vibeguard doctor
```

`doctor` verifies your Node version, finds your key, confirms it authenticates,
and sends one real request to prove you have generation quota — so a depleted
project shows up before it silently degrades a scan.

---

## Usage

```bash
vibeguard scan .                    # audit the current directory
vibeguard scan ./services/api       # report is written into ./services/api
vibeguard scan . --no-ai            # pattern engine only, zero network calls
vibeguard scan . --fail-on high     # exit 1 if anything high or critical is found
vibeguard scan . --quiet            # one-line output, for scripts
vibeguard scan . -o AUDIT.md        # custom report filename
```

### Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-k, --key <key>` | — | Gemini API key for this run |
| `-m, --model <model>` | `gemini-3.6-flash` | Gemini model (falls back automatically if unavailable) |
| `--no-ai` | — | Skip the Gemini pass entirely |
| `--no-json` | — | Write only the Markdown report |
| `-o, --output <file>` | `SECURITY-REPORT.md` | Markdown report filename |
| `-c, --concurrency <n>` | `4` | Parallel Gemini requests |
| `--ai-budget <chars>` | `400000` | Cap on source characters sent to Gemini |
| `--max-files <n>` | `4000` | Stop discovery after N files |
| `--fail-on <severity>` | — | Exit 1 at or above `critical`/`high`/`medium`/`low` |
| `--quiet` | — | Suppress banner and finding list |

---

## How a scan works

1. **Discovery** — walks the tree concurrently, skipping `node_modules`, build
   output, lockfiles, binaries and VibeGuard's own reports.
2. **Pattern engine** — ~30 rules across secrets, injection, XSS, access control,
   cryptography, misconfiguration and LLM-specific risks. Deterministic, offline,
   sub-second on a typical repo.
3. **Risk ranking** — files are scored by static hits, path (`api/`, `auth/`,
   `admin/`), and content signals (`req.body`, prompt construction, `exec(`).
4. **Gemini review** — the highest-risk files are batched and sent in parallel
   with a JSON response schema. Findings that name a file outside the scan or a
   line beyond the file's length are discarded rather than reported.
5. **Report** — findings are deduplicated, severity-sorted, scored 0–100, and
   written into the scanned folder.

If the AI pass fails for any reason — no key, no quota, network down — the scan
completes on the pattern engine and tells you exactly what happened and how to
fix it. It never leaves you without a report.

---

## The report

`SECURITY-REPORT.md` contains a verdict and score, a severity table, a ranked
"fix these first" list, a per-file index, and a detail section for each finding
with the vulnerable line, the exploit path, a CWE link, and a concrete fix.

`vibeguard-report.json` carries the same data machine-readably:

```jsonc
{
  "securityScore": 42,
  "verdict": "DANGEROUS",
  "vulnerabilityCounts": { "CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 0 },
  "vulnerabilities": [
    {
      "id": "VG-INJ-001",
      "title": "SQL query built by string concatenation",
      "severity": "CRITICAL",
      "category": "Injection",
      "cwe": "CWE-89",
      "file": "src/api/users.js",
      "line": 12,
      "code": "db.raw(\"SELECT * FROM users WHERE id=\" + req.query.id)",
      "description": "...",
      "fix": "...",
      "source": "static"
    }
  ]
}
```

`source` is `"static"` for pattern-engine findings and `"gemini"` for AI ones
(which also carry a `confidence` field).

---

## CI

```yaml
- run: npx -y @vidhaankhare/vibeguard scan . --no-ai --fail-on high --quiet
```

`--no-ai` keeps CI deterministic and free. Drop it and set `GEMINI_API_KEY` as a
secret if you want the AI pass on every build.

---

## What it does not do

VibeGuard is a fast first pass, not an assurance process. It does not resolve
dependency CVEs (use `npm audit`), does not execute your code, and cannot prove
the absence of vulnerabilities. A clean report means nothing was found in the
files that were analysed.

---

## Development

```bash
npm install
npm test        # 66 assertions across detection, scoring, reporting and the Gemini transport — no network
npm start       # scan the current directory
```

MIT © Vidhaan Khare
