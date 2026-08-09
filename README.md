# VibeGuard — https://website-vidhaan-khares-projects.vercel.app/

**Gemini-powered security auditing for AI-generated code.**

Point VibeGuard at a folder. It reads the code, finds the vulnerabilities, and writes
a Markdown report **into that same folder**.

Standard security tools assume modular architecture and an experienced author.
VibeGuard targets the failure modes AI-authored code actually exhibits: endpoints that
mutate data with no auth check, keys pasted into source, user text concatenated into
LLM prompts, and insecure defaults copied wholesale from tutorials.

---

## Quick start

```bash
# Audit the current directory — writes SECURITY-REPORT.md here
npx @vidhaankhare/vibeguard scan .
```

The pattern engine runs with no setup. To turn on the Gemini review pass:

```bash
npx @vidhaankhare/vibeguard auth <your-gemini-api-key>   # free: https://aistudio.google.com/apikey
npx @vidhaankhare/vibeguard doctor                       # verify key, quota and models
```

Your key is stored in `~/.vibeguard/config.json` — never in the project you scan.

---

## Project structure

```
vibeguard-cli/   ← The CLI tool (npm package: @vidhaankhare/vibeguard)
skills/          ← OpenClaw agent skill (drop-in security auditing for AI agents)
website/         ← Marketing landing page (open index.html in a browser)
```

---

## CLI usage

```bash
npx @vidhaankhare/vibeguard scan .        # audit current directory
npm install -g @vidhaankhare/vibeguard    # or install globally

vibeguard scan ./my-app                   # report is written into ./my-app
vibeguard scan . --no-ai                  # pattern engine only, no network calls
vibeguard scan . --fail-on high           # exit 1 on high/critical — for CI
vibeguard scan . --quiet                  # single-line output for scripts
vibeguard doctor                          # health-check key, quota and models
vibeguard --help
```

Full flag reference: [`vibeguard-cli/README.md`](vibeguard-cli/README.md).

---

## How it works

| Stage | What happens |
| :--- | :--- |
| **1. Discovery** | Concurrent tree walk, skipping `node_modules`, build output, lockfiles and binaries. |
| **2. Pattern engine** | ~30 deterministic rules — secrets, injection, XSS, access control, crypto, misconfiguration, LLM risks. Sub-second on a typical repo. |
| **3. Risk ranking** | Files scored by static hits, path (`api/`, `auth/`, `admin/`) and content signals (`req.body`, prompt building, `exec(`). |
| **4. Gemini review** | Highest-risk files batched and sent in parallel with a strict JSON response schema. Findings pointing at non-existent files or lines are discarded. |
| **5. Report** | Findings deduplicated, severity-sorted, scored 0–100, written into the scanned folder. |

If the AI pass can't run — no key, no quota, no network — the scan finishes on the
pattern engine and tells you exactly what failed and how to fix it. You always get a
report.

---

## What it detects

**Secrets** — AWS, Google/Gemini, OpenAI, Anthropic, GitHub, Stripe, Slack, SendGrid
and Twilio credentials; private keys; database URIs with embedded passwords; generic
high-entropy assignments; and server secrets leaked to the browser through
`NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` prefixes.

**Injection** — SQL built by concatenation, shell commands from untrusted input,
`shell=True`, `eval` / `new Function`, unsafe deserialization, and NoSQL operator
injection through raw request objects.

**Access control** — mutating API routes with no authentication anywhere in the file,
stubbed or hardcoded authorization checks, public Firebase/Firestore rules.

**LLM security** — user input interpolated into system prompts, and model output
flowing into `eval`, a shell, a query, or the DOM.

**Crypto & auth** — JWTs decoded without verification, MD5/SHA-1 password hashing,
`Math.random()` for tokens, insecure cookie flags.

**Misconfiguration** — wildcard CORS, disabled TLS verification, debug mode on,
wildcard host allow-lists, `chmod 777`, containers running as root.

---

## Output

Every scan writes into the scanned directory:

- **`SECURITY-REPORT.md`** — verdict and 0–100 score, severity table, ranked
  "fix these first" list, per-file index, and full detail per finding with the
  vulnerable line, exploit path, CWE link and a concrete fix.
- **`vibeguard-report.json`** — the same data machine-readably, for CI and agents.

Add `vibeguard-report.*` and `SECURITY-REPORT.md` to `.gitignore` if you scan often.

---

## Use with OpenClaw (agentic harness)

VibeGuard ships as a drop-in [OpenClaw](https://openclaw.ai) skill, so any OpenClaw
agent can security-audit code it just generated — closing the loop between
*AI writes code* and *AI ships insecure code*.

```bash
# From this repo — copy the skill into your OpenClaw skills directory
cp -r skills/vibeguard ~/.openclaw/skills/vibeguard

# Or into a single agent's workspace
cp -r skills/vibeguard <workspace>/skills/vibeguard
```

Then tell your agent things like:

> "vibe-check this project before we deploy"
> "scan the code you just wrote and fix anything critical"

See [`skills/vibeguard/SKILL.md`](skills/vibeguard/SKILL.md) for the full definition.

---

## CI

```yaml
- run: npx -y @vidhaankhare/vibeguard scan . --no-ai --fail-on high --quiet
```

`--no-ai` keeps CI deterministic and free. Drop it and set `GEMINI_API_KEY` as a
repository secret to run the AI pass on every build.

---

## Running locally

```bash
cd vibeguard-cli
npm install
npm test                 # 71 assertions, no network required
node bin/index.js scan .
```

Or link it globally:

```bash
cd vibeguard-cli && npm link
vibeguard scan .
```

## Publishing

```bash
cd vibeguard-cli
npm login
npm publish --access public
```

---

## The landing page

Open `website/index.html` directly in any browser — no build step required.

---

## Limits

VibeGuard is a fast first pass, not an assurance process. It does not resolve
dependency CVEs (use `npm audit`), does not execute your code, and cannot prove the
absence of vulnerabilities. A clean report means nothing was found in the files that
were analysed.

---

## The problem VibeGuard solves

- AI-generated code contains **2.74× more security vulnerabilities** than human-written code (CodeRabbit, 2025)
- **45%** of AI-generated applications contain exploitable OWASP vulnerabilities (Veracode, 2025)
- **5,000** vibe-coded apps were found with virtually no security or authentication (Dor Zvi, 2026)
- **322%** more privilege escalation paths in AI code than human-written code (Apiiro, 2025)

---

MIT Licensed · © 2026 Vidhaan Khare
