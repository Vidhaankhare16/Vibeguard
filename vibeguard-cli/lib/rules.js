// ============================================================
// VibeGuard — static detection engine
//
// Real line-by-line pattern analysis. Every rule carries a severity, a CWE
// reference and a concrete remediation. Rules are precompiled once and run
// against each line; a whole mid-size repo scans in well under a second.
// ============================================================

const JS_LIKE = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte', '.astro'];
const PY = ['.py'];
const WEB = [...JS_LIKE, '.html', '.htm', '.ejs', '.hbs'];

// Values that look like secrets but are obviously not.
const PLACEHOLDER = /^(your|my|the|some|xxx+|placeholder|change[_-]?me|example|sample|test|dummy|fake|dev|demo|todo|none|null|undefined|true|false|abc|123|foo|bar|\.\.\.|<|\{|\$\{|process\.env|import\.meta|os\.environ|env\[|config\.|secret|password|token|apikey|api[_-]key)/i;

// Files where fake credentials are expected and not a finding.
const FIXTURE_PATH = /(^|\/)(test|tests|__tests__|spec|specs|fixtures?|mocks?|examples?|docs?|samples?)\//i;
const EXAMPLE_ENV = /\.env\.(example|sample|template|dist)$/i;

function hasHighEntropy(value) {
  if (value.length < 16) return false;
  const freq = new Map();
  for (const ch of value) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy > 3.2;
}

/**
 * Rule shape:
 *   id       stable identifier, used for --ignore and dedupe
 *   pattern  RegExp run against a single line
 *   exts     optional extension allow-list
 *   confirm  optional (match, line, file) => boolean, for false-positive control
 */
export const RULES = [
  // ---------------------------------------------------------------- secrets
  {
    id: 'VG-SEC-001',
    title: 'Hardcoded AWS access key ID',
    severity: 'CRITICAL',
    category: 'Secrets',
    cwe: 'CWE-798',
    pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
    description: 'An AWS access key ID is committed in source. Anyone with repository access — or anyone who pulls the published package — can assume these credentials.',
    fix: 'Revoke the key in the AWS IAM console immediately, then load credentials from the environment or an instance role. Rotating is not optional: assume the key is compromised.',
  },
  {
    id: 'VG-SEC-002',
    title: 'Hardcoded Google API key',
    severity: 'CRITICAL',
    category: 'Secrets',
    cwe: 'CWE-798',
    pattern: /\b(AIza[0-9A-Za-z\-_]{35}|AQ\.[A-Za-z0-9_\-]{30,})/,
    description: 'A Google / Gemini API key is hardcoded. Keys in source are billable by whoever finds them.',
    fix: 'Delete the key from the code and revoke it at https://aistudio.google.com/apikey. Read it from `process.env.GEMINI_API_KEY` instead.',
  },
  {
    id: 'VG-SEC-003',
    title: 'Hardcoded OpenAI / Anthropic API key',
    severity: 'CRITICAL',
    category: 'Secrets',
    cwe: 'CWE-798',
    pattern: /\bsk-(ant-)?(proj-|api03-)?[A-Za-z0-9_\-]{24,}\b/,
    description: 'An LLM provider API key is embedded in source. These keys carry direct billing and are actively scraped from public repositories within minutes of a push.',
    fix: 'Revoke the key in the provider console and move it to an environment variable. Never ship provider keys to a client bundle — proxy LLM calls through your backend.',
  },
  {
    id: 'VG-SEC-004',
    title: 'Hardcoded GitHub token',
    severity: 'CRITICAL',
    category: 'Secrets',
    cwe: 'CWE-798',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
    description: 'A GitHub personal access / OAuth token is present in source, granting repository access to anyone who reads this file.',
    fix: 'Revoke the token at github.com/settings/tokens and replace it with a short-lived Actions token or a secret store reference.',
  },
  {
    id: 'VG-SEC-005',
    title: 'Hardcoded Stripe live secret key',
    severity: 'CRITICAL',
    category: 'Secrets',
    cwe: 'CWE-798',
    pattern: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/,
    description: 'A live Stripe secret key is hardcoded. This permits charges, refunds and customer data reads against the production account.',
    fix: 'Roll the key in the Stripe dashboard right now and load it from the environment. Only the publishable key (`pk_`) may reach client code.',
  },
  {
    id: 'VG-SEC-006',
    title: 'Private key material committed',
    severity: 'CRITICAL',
    category: 'Secrets',
    cwe: 'CWE-798',
    pattern: /-----BEGIN ((RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)\s+)?PRIVATE KEY-----/,
    description: 'A private key block is stored in the repository. Signing keys and TLS keys in version control cannot be un-leaked.',
    fix: 'Generate a replacement key pair, rotate every service trusting the old key, and purge the file from git history (`git filter-repo`).',
  },
  {
    id: 'VG-SEC-007',
    title: 'Slack / SendGrid / Twilio token in source',
    severity: 'HIGH',
    category: 'Secrets',
    cwe: 'CWE-798',
    pattern: /\b(xox[baprs]-[A-Za-z0-9\-]{10,}|SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}|SK[0-9a-fA-F]{32})\b/,
    description: 'A third-party service token is hardcoded, allowing anyone with the file to send messages or email as your application.',
    fix: 'Revoke the token in the provider dashboard and load it from the environment at runtime.',
  },
  {
    id: 'VG-SEC-008',
    title: 'Database connection string with embedded credentials',
    severity: 'CRITICAL',
    category: 'Secrets',
    cwe: 'CWE-798',
    pattern: /\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp):\/\/[^\s'"@:]+:[^\s'"@]+@/i,
    description: 'A database URI containing a username and password is hardcoded, exposing direct database access.',
    fix: 'Move the full connection string to an environment variable and rotate the database password.',
  },
  {
    id: 'VG-SEC-009',
    title: 'Generic hardcoded credential',
    severity: 'HIGH',
    category: 'Secrets',
    cwe: 'CWE-798',
    // Leading `[A-Za-z0-9_]*` so camelCase names like `jwtSecret` still match.
    pattern: /(?:^|[^A-Za-z0-9_])[A-Za-z0-9_]*(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)[A-Za-z0-9_]*\s*[:=]\s*['"`]([^'"`\n]{8,})['"`]/i,
    confirm: (match, _line, file) => {
      const value = match[2];
      if (PLACEHOLDER.test(value)) return false;
      if (/^\$?\{|\}$/.test(value)) return false;
      if (EXAMPLE_ENV.test(file.rel) || FIXTURE_PATH.test(file.rel)) return false;
      // Real credentials are either high-entropy or long and mixed-character.
      const mixed = /[a-z]/.test(value) && /[A-Z0-9]/.test(value) && value.length >= 12;
      return hasHighEntropy(value) || mixed;
    },
    description: 'A credential is assigned a literal string value in source rather than being read from configuration.',
    fix: 'Replace the literal with an environment variable lookup and rotate the credential, since it is already in version control history.',
  },
  {
    id: 'VG-SEC-010',
    title: 'Secret exposed to the client bundle',
    severity: 'CRITICAL',
    category: 'Secrets',
    cwe: 'CWE-200',
    pattern: /\b(NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(SECRET|PRIVATE|API_?KEY|TOKEN|PASSWORD|SERVICE_ROLE)[A-Z0-9_]*\b/,
    description: 'A variable prefixed for client-side exposure holds a secret. Every framework listed here inlines these values into the JavaScript bundle shipped to browsers, so the value is public.',
    fix: 'Drop the public prefix and read the secret only in server code (route handler, server action, or API route). Rotate the value — assume it has already shipped to users.',
  },

  // -------------------------------------------------------------- injection
  {
    id: 'VG-INJ-001',
    title: 'SQL query built by string concatenation',
    severity: 'CRITICAL',
    category: 'Injection',
    cwe: 'CWE-89',
    pattern: /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE)\b[^;'"`\n]{0,120}(\$\{|["'`]\s*\+|%s|%\(|\+\s*(req|request|params|query|body|input|user))/i,
    // Marketing pages and docs quote vulnerable snippets as examples.
    exts: [...JS_LIKE, ...PY, '.php', '.go', '.java', '.cs', '.rb', '.rs', '.sql', '.ts'],
    description: 'User-controllable data is interpolated directly into a SQL statement. An attacker can terminate the intended query and append their own — reading, altering or deleting arbitrary rows.',
    fix: 'Use parameterised queries (`db.query("… WHERE id = $1", [id])`) or an ORM. Never build SQL with template literals or `+`.',
  },
  {
    id: 'VG-INJ-002',
    title: 'Shell command built from untrusted input',
    severity: 'CRITICAL',
    category: 'Injection',
    cwe: 'CWE-78',
    pattern: /\b(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*[`"'][^`"']*(\$\{|["']\s*\+)/,
    exts: JS_LIKE,
    description: 'A shell command is assembled from interpolated data. Shell metacharacters (`;`, `|`, `$()`) in that data run as additional commands with the process\'s privileges.',
    fix: 'Use `execFile`/`spawn` with an argument array and no shell, and validate inputs against an allow-list.',
  },
  {
    id: 'VG-INJ-003',
    title: 'Python shell execution with shell=True',
    severity: 'HIGH',
    category: 'Injection',
    cwe: 'CWE-78',
    pattern: /\b(subprocess\.(run|call|Popen|check_output)[^\n]*shell\s*=\s*True|os\.(system|popen)\s*\()/,
    exts: PY,
    description: 'A shell is spawned to run a command string. If any part of that string is user-influenced, this is remote command execution.',
    fix: 'Pass the command as a list with `shell=False` (the default) and validate arguments.',
  },
  {
    id: 'VG-INJ-004',
    title: 'Dynamic code execution via eval / new Function',
    severity: 'HIGH',
    category: 'Injection',
    cwe: 'CWE-95',
    pattern: /(^|[^.\w])(eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`])/,
    exts: JS_LIKE,
    description: 'The code evaluates a string as JavaScript. Any attacker influence over that string becomes arbitrary code execution in your process.',
    fix: 'Replace `eval` with explicit parsing — `JSON.parse` for data, a lookup map for dispatch, and a real function reference for timers.',
  },
  {
    id: 'VG-INJ-005',
    title: 'Unsafe deserialization',
    severity: 'CRITICAL',
    category: 'Injection',
    cwe: 'CWE-502',
    pattern: /\b(pickle\.loads?|yaml\.load\s*\((?![^)]*Safe)|marshal\.loads|cPickle\.loads)\b/,
    exts: PY,
    description: 'Untrusted bytes are deserialized with a format that can instantiate arbitrary objects, which is directly exploitable for code execution.',
    fix: 'Use `json.loads` for data interchange, or `yaml.safe_load` for YAML. Never unpickle data you did not produce.',
  },
  {
    id: 'VG-INJ-006',
    title: 'NoSQL query built from raw request object',
    severity: 'HIGH',
    category: 'Injection',
    cwe: 'CWE-943',
    pattern: /\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany)\s*\(\s*(req\.(body|query|params)|request\.(body|query|params))\s*[,)]/,
    exts: JS_LIKE,
    description: 'A request object is passed straight into a database query. An attacker can submit operator objects such as `{"$ne": null}` to bypass the intended filter — including login checks.',
    fix: 'Extract and cast individual fields explicitly, or validate the payload with a schema (Zod, Joi) before querying.',
  },

  // -------------------------------------------------------------------- XSS
  {
    id: 'VG-XSS-001',
    title: 'dangerouslySetInnerHTML with interpolated value',
    severity: 'HIGH',
    category: 'XSS',
    cwe: 'CWE-79',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*(?!['"`])/,
    exts: JS_LIKE,
    description: 'React\'s HTML escape hatch is fed a dynamic value. If that value ever contains user content, it executes as markup and script in every viewer\'s browser.',
    fix: 'Render the value as text, or sanitise with DOMPurify before assignment.',
  },
  {
    id: 'VG-XSS-002',
    title: 'innerHTML / document.write assigned dynamic content',
    severity: 'HIGH',
    category: 'XSS',
    cwe: 'CWE-79',
    pattern: /(?:\.(?:innerHTML|outerHTML)\s*\+?=\s*(.+)$|document\.write\s*\()/,
    exts: WEB,
    confirm: (match) => {
      const rhs = match[1]?.trim();
      if (!rhs) return true; // document.write — always worth reporting
      // A quoted literal with no interpolation or concatenation is static markup.
      const literal = /^(['"`])(?:(?!\1)[\s\S])*\1\s*;?$/.test(rhs);
      if (literal && !rhs.includes('${') && !rhs.includes('+')) return false;
      return true;
    },
    description: 'Markup is written into the DOM from a variable. Attacker-supplied strings become live HTML, enabling session theft and account takeover.',
    fix: 'Use `textContent` for text, or `DOMPurify.sanitize()` when HTML is genuinely required.',
  },

  // ----------------------------------------------------------- misconfig
  {
    id: 'VG-CFG-001',
    title: 'Wildcard CORS policy',
    severity: 'HIGH',
    category: 'Misconfiguration',
    cwe: 'CWE-942',
    // Covers header objects, setHeader(name, value) calls and cors() options.
    pattern: /(Access-Control-Allow-Origin['"`]?\s*[,:=]\s*['"`]\*|cors\s*\(\s*\{[^}]*origin\s*:\s*(['"`]\*['"`]|true))/i,
    description: 'Any website can issue cross-origin requests to this service. Combined with cookie authentication this allows a malicious page to act as the logged-in user.',
    fix: 'Replace the wildcard with an explicit allow-list of your own origins, and only enable `credentials` for those.',
  },
  {
    id: 'VG-CFG-002',
    title: 'TLS certificate verification disabled',
    severity: 'HIGH',
    category: 'Misconfiguration',
    cwe: 'CWE-295',
    pattern: /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"`]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|curl[^\n]*\s-k\b)/,
    description: 'Certificate validation is turned off, so the connection accepts any certificate. This removes all protection against man-in-the-middle interception.',
    fix: 'Remove the flag. If a self-signed certificate is genuinely needed, pin that specific CA instead of disabling verification.',
  },
  {
    id: 'VG-CFG-003',
    title: 'Debug mode enabled in configuration',
    severity: 'MEDIUM',
    category: 'Misconfiguration',
    cwe: 'CWE-489',
    pattern: /^\s*(DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\([^)]*debug\s*=\s*True)/,
    description: 'Debug mode is on. Frameworks expose stack traces, source snippets and — in Flask\'s case — an interactive console that executes code.',
    fix: 'Drive the flag from an environment variable that defaults to off, and ensure production sets it to false.',
  },
  {
    id: 'VG-CFG-004',
    title: 'Host allow-list set to wildcard',
    severity: 'MEDIUM',
    category: 'Misconfiguration',
    cwe: 'CWE-16',
    pattern: /ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]/,
    description: 'The application answers requests for any Host header, enabling host-header poisoning of password-reset links and cache entries.',
    fix: 'List your real domains explicitly in `ALLOWED_HOSTS`.',
  },
  {
    id: 'VG-CFG-005',
    title: 'Public read/write database security rules',
    severity: 'CRITICAL',
    category: 'Access Control',
    cwe: 'CWE-284',
    pattern: /allow\s+(read|write|read,\s*write|create|update|delete)[^;:]*:\s*if\s+true/,
    description: 'A Firebase/Firestore rule grants unauthenticated access to the whole collection. Anyone with your project ID can read and wipe the database.',
    fix: 'Gate every rule on `request.auth != null` and on document ownership.',
  },
  {
    id: 'VG-CFG-006',
    title: 'World-writable permissions',
    severity: 'MEDIUM',
    category: 'Misconfiguration',
    cwe: 'CWE-732',
    pattern: /chmod\s+(-R\s+)?777\b/,
    description: 'Files are made writable by every user on the host, allowing local privilege escalation through modified application code.',
    fix: 'Grant the narrowest permission that works — usually `755` for directories and `644` for files.',
  },
  {
    id: 'VG-CFG-007',
    title: 'Container runs as root',
    severity: 'MEDIUM',
    category: 'Misconfiguration',
    cwe: 'CWE-250',
    pattern: /^\s*USER\s+root\s*$|--privileged\b/,
    description: 'The container process runs with root privileges, so a code-execution bug becomes host-level compromise far more easily.',
    fix: 'Create an unprivileged user in the Dockerfile and switch to it with `USER app` before `CMD`.',
  },

  // ------------------------------------------------------- authn / crypto
  {
    id: 'VG-AUT-001',
    title: 'JWT decoded without signature verification',
    severity: 'CRITICAL',
    category: 'Authentication',
    cwe: 'CWE-347',
    pattern: /jwt\.decode\s*\(|verify\s*\([^)]*algorithms\s*:\s*\[\s*['"`]none['"`]|verify_signature['"`]?\s*:\s*False/i,
    description: 'A token is read without checking its signature. An attacker can hand-craft a token claiming any user ID or role and be trusted.',
    fix: 'Use `jwt.verify(token, secret, { algorithms: ["HS256"] })` and pin the expected algorithm explicitly.',
  },
  {
    id: 'VG-AUT-002',
    title: 'Weak hash used for passwords',
    severity: 'HIGH',
    category: 'Cryptography',
    cwe: 'CWE-916',
    pattern: /createHash\s*\(\s*['"`](md5|sha1)['"`]|hashlib\.(md5|sha1)\s*\(/i,
    description: 'A fast general-purpose hash is used where a password hash is required. Commodity GPUs test billions of these per second, so leaked hashes are cracked immediately.',
    fix: 'Use bcrypt, scrypt or Argon2id with a per-user salt and a work factor tuned to ~250ms.',
  },
  {
    id: 'VG-AUT-003',
    title: 'Math.random() used for security value',
    severity: 'HIGH',
    category: 'Cryptography',
    cwe: 'CWE-338',
    pattern: /(token|secret|key|nonce|salt|otp|code|session|password|reset|id)\s*[:=][^;\n]*Math\.random\s*\(/i,
    exts: JS_LIKE,
    description: '`Math.random()` is not cryptographically secure — its output is predictable from prior values, so generated tokens can be guessed.',
    fix: 'Use `crypto.randomUUID()` or `crypto.randomBytes(32).toString("hex")`.',
  },
  {
    id: 'VG-AUT-004',
    title: 'Insecure cookie configuration',
    severity: 'MEDIUM',
    category: 'Authentication',
    cwe: 'CWE-1004',
    pattern: /(httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*['"`]none['"`])/i,
    exts: JS_LIKE,
    description: 'A session cookie is readable by JavaScript, sent over plaintext, or attached to cross-site requests — each of which widens session-hijacking exposure.',
    fix: 'Set `httpOnly: true`, `secure: true` and `sameSite: "lax"` on all authentication cookies.',
  },
  {
    id: 'VG-AUT-005',
    title: 'Authentication check disabled or bypassed',
    severity: 'CRITICAL',
    category: 'Access Control',
    cwe: 'CWE-306',
    pattern: /(\/\/\s*(TODO|FIXME|HACK)[^\n]*\b(auth|permission|security|validat)|(isAdmin|isAuthenticated|requireAuth|checkAuth|authorized)\s*[:=]\s*true\s*[;,]|if\s*\(\s*(true|1)\s*\)\s*\{?\s*(\/\/)?\s*(allow|grant|bypass))/i,
    description: 'An authorization check is stubbed out, hardcoded to pass, or flagged as unfinished. AI-generated scaffolding frequently leaves these behind and they ship as-is.',
    fix: 'Implement the real check against the session before this code path can run, and add a test that asserts an anonymous request is rejected.',
  },

  // ------------------------------------------------------------- AI-specific
  {
    id: 'VG-AI-001',
    title: 'Unsanitized user input interpolated into an LLM prompt',
    severity: 'HIGH',
    category: 'LLM Security',
    cwe: 'CWE-1427',
    pattern: /(system_?[Pp]rompt|systemInstruction|prompt|instructions?)\s*[:=][^\n]*`[^`\n]*\$\{/,
    exts: JS_LIKE,
    description: 'User-controllable text is concatenated into a prompt or system instruction. An attacker can inject instructions that override your intent — leaking the system prompt, exfiltrating context, or abusing any tool the model can call.',
    fix: 'Keep instructions in the `system` role and pass user text as a separate `user` message. Validate length and strip control sequences, and never let model output reach a shell, SQL query or `eval`.',
  },
  {
    id: 'VG-AI-002',
    title: 'LLM output passed to a dangerous sink',
    severity: 'CRITICAL',
    category: 'LLM Security',
    cwe: 'CWE-94',
    pattern: /(eval|exec|execSync|spawn|Function|query|innerHTML)\s*\(\s*[^)]*\b(completion|response|llmOutput|aiResponse|choices\[0\]|message\.content|generatedText|result\.text)\b/,
    exts: JS_LIKE,
    description: 'Text generated by a language model flows into code execution, a query, or the DOM. Because prompts are attacker-influenceable, this is an indirect remote-execution path.',
    fix: 'Treat model output as untrusted input: parse it into a strict schema, validate against an allow-list, and never execute it directly.',
  },
  {
    id: 'VG-AI-003',
    title: 'Missing authentication on a mutating API route',
    severity: 'HIGH',
    category: 'Access Control',
    cwe: 'CWE-306',
    // Handled by a file-level detector below; kept here for documentation.
    pattern: null,
    description: 'An API route performs writes but contains no authentication or session check.',
    fix: 'Wrap the handler in your auth middleware and reject requests without a valid session before any mutation runs.',
  },
];

const COMPILED = RULES.filter((r) => r.pattern);

// ---------------------------------------------------------------- file-level

const API_ROUTE = /(^|\/)(api|routes?|controllers?|handlers?|endpoints?|functions?)\//i;
const MUTATION = /\b(POST|PUT|PATCH|DELETE)\b|\.(create|update|delete|destroy|insert|remove|save|drop|truncate)\s*\(|export\s+async\s+function\s+(POST|PUT|PATCH|DELETE)\b/;
const AUTH_HINT = /\b(auth|session|token|jwt|verify|authenticate|authorize|getServerSession|currentUser|requireUser|clerk|passport|withAuth|isAdmin|permission|guard|middleware|bearer|apiKey|x-api-key)\b/i;

function detectUnauthenticatedRoute(file) {
  if (!API_ROUTE.test(file.rel)) return null;
  if (!MUTATION.test(file.content)) return null;
  if (AUTH_HINT.test(file.content)) return null;

  const lines = file.content.split(/\r?\n/);
  const idx = lines.findIndex((l) => MUTATION.test(l));
  const rule = RULES.find((r) => r.id === 'VG-AI-003');

  return {
    ...ruleToFinding(rule, file, idx === -1 ? 1 : idx + 1, (lines[idx] || '').trim()),
    description:
      `\`${file.rel}\` sits on an API route path and performs mutating operations, but the file contains no authentication, session or token check. ` +
      'Any anonymous request that reaches this endpoint executes the mutation. This is the single most common defect in AI-generated backends, because the model completes the file it was asked for without the surrounding authorization layer.',
  };
}

function detectCommittedEnv(file) {
  if (!/(^|\/)\.env(\.local|\.production|\.development)?$/.test(file.rel)) return null;
  const hasValue = /^\s*[A-Z0-9_]+\s*=\s*\S+/m.test(file.content);
  if (!hasValue) return null;

  return {
    id: 'VG-SEC-011',
    title: 'Environment file present in the scanned tree',
    severity: 'HIGH',
    category: 'Secrets',
    cwe: 'CWE-538',
    file: file.rel,
    line: 1,
    code: '(contents withheld)',
    description:
      `\`${file.rel}\` contains populated environment values. If this file is not in \`.gitignore\` it will be committed, and every value in it must be treated as public.`,
    fix: 'Confirm `.env*` is git-ignored, commit only a `.env.example` with empty values, and rotate anything that has already been pushed.',
    source: 'static',
  };
}

const FILE_DETECTORS = [detectUnauthenticatedRoute, detectCommittedEnv];

// ---------------------------------------------------------------- execution

function ruleToFinding(rule, file, line, code) {
  return {
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.category,
    cwe: rule.cwe,
    file: file.rel,
    line,
    code,
    description: rule.description,
    fix: rule.fix,
    source: 'static',
  };
}

const MAX_PER_RULE_PER_FILE = 3;
const CODE_MAX = 220;

/** Run every rule over one file. Returns an array of findings. */
export function scanFile(file) {
  const findings = [];
  const lines = file.content.split(/\r?\n/);
  const seenPerRule = new Map();
  const isFixture = FIXTURE_PATH.test(file.rel) || EXAMPLE_ENV.test(file.rel);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.length > 2000) continue;

    // Skip pure comment lines for non-secret rules later; cheap check now.
    const trimmed = line.trim();

    for (const rule of COMPILED) {
      if (rule.exts && !rule.exts.includes(file.ext)) continue;

      const count = seenPerRule.get(rule.id) || 0;
      if (count >= MAX_PER_RULE_PER_FILE) continue;

      const match = rule.pattern.exec(line);
      if (!match) continue;
      if (rule.confirm && !rule.confirm(match, line, file)) continue;

      // Fixture/example paths only report the highest-signal secret rules.
      if (isFixture && rule.category === 'Secrets' && rule.severity !== 'CRITICAL') continue;

      seenPerRule.set(rule.id, count + 1);
      findings.push(
        ruleToFinding(
          rule,
          file,
          i + 1,
          trimmed.length > CODE_MAX ? `${trimmed.slice(0, CODE_MAX)}…` : trimmed
        )
      );
    }
  }

  for (const detector of FILE_DETECTORS) {
    const finding = detector(file);
    if (finding) findings.push(finding);
  }

  return findings;
}

/** Run the static engine across all files. */
export function scanAll(files) {
  const findings = [];
  for (const file of files) {
    try {
      findings.push(...scanFile(file));
    } catch {
      /* a single bad file must never abort the scan */
    }
  }
  return findings;
}

export const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const s = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (s !== 0) return s;
    const f = a.file.localeCompare(b.file);
    if (f !== 0) return f;
    return (a.line || 0) - (b.line || 0);
  });
}

/** Collapse duplicates reported by both the static engine and the AI pass. */
export function dedupe(findings) {
  const seen = new Map();
  for (const finding of findings) {
    const key = `${finding.file}:${finding.line}:${(finding.category || '').toLowerCase()}`;
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, finding);
      continue;
    }
    // Prefer the static finding (verified pattern) but keep AI's richer prose.
    if (existing.source !== 'static' && finding.source === 'static') {
      seen.set(key, { ...finding, description: existing.description || finding.description });
    }
  }
  return [...seen.values()];
}

/**
 * 0–100 score. Starts at 100 and subtracts weighted penalties with
 * diminishing returns, so one CRITICAL is alarming but ten is not 20x worse.
 */
export function scoreOf(findings, fileCount) {
  const weights = { CRITICAL: 25, HIGH: 10, MEDIUM: 4, LOW: 1, INFO: 0 };
  let penalty = 0;
  const counted = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

  for (const finding of findings) {
    const severity = finding.severity in weights ? finding.severity : 'LOW';
    const n = counted[severity]++;
    penalty += weights[severity] * Math.pow(0.75, n); // diminishing returns
  }

  // Very small projects shouldn't be scored as harshly as a whole monorepo.
  const scale = fileCount < 5 ? 0.8 : 1;
  return Math.max(0, Math.min(100, Math.round(100 - penalty * scale)));
}

/**
 * The pattern engine cannot see authorization gaps, broken ownership checks or
 * logic flaws — only the AI pass can. So a pattern-only scan that finds nothing
 * must not report a clean bill of health: on a fixture containing IDOR, mass
 * assignment and a double-spend race, the pattern engine correctly returns zero,
 * and a naive verdict turns that into "100/100 STRONG". Since running without a
 * key is the default, that reassuring green score is what most users would see.
 *
 * `aiRan: false` therefore downgrades a quiet result to an explicit statement of
 * what was not checked, rather than a score implying it was.
 */
export function verdictOf(score, aiRan = true) {
  if (!aiRan && score >= 90) {
    return {
      label: 'INCOMPLETE',
      blurb:
        'Nothing matched the pattern rules — but AI review did not run, so authorization gaps, broken ownership checks and logic flaws were never checked. This is not a clean bill of health.',
      partial: true,
    };
  }

  const verdict =
    score >= 90 ? { label: 'STRONG', blurb: 'No serious issues surfaced. Keep scanning as the codebase grows.' }
    : score >= 75 ? { label: 'FAIR', blurb: 'A few real weaknesses to close, but nothing that blocks a careful release.' }
    : score >= 50 ? { label: 'AT RISK', blurb: 'Meaningful vulnerabilities are present. Fix the high-severity findings before deploying.' }
    : score >= 25 ? { label: 'DANGEROUS', blurb: 'Multiple exploitable issues. This codebase should not face the public internet as-is.' }
    : { label: 'CRITICAL', blurb: 'Severe, directly exploitable vulnerabilities. Treat any deployed instance as already compromised.' };

  if (!aiRan) {
    return {
      ...verdict,
      partial: true,
      blurb: `${verdict.blurb} Pattern analysis only — AI review did not run, so logic and authorization flaws are not covered.`,
    };
  }
  return verdict;
}
