// ============================================================
// VibeGuard — self-test
//
// Runs the detection engine against known-vulnerable and known-clean samples
// so rule changes can't silently regress. No network, no API key needed.
//   node test/run.js
// ============================================================

import assert from 'node:assert/strict';
import { scanFile, scoreOf, dedupe, sortFindings, verdictOf } from '../lib/rules.js';
import { buildMarkdown } from '../lib/report.js';
import { buildBatches, explainApiError } from '../lib/gemini.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL ${name}`);
    console.log(`       ${err.message.split('\n')[0]}`);
  }
}

const file = (rel, content) => ({
  rel,
  name: rel.split('/').pop(),
  ext: `.${rel.split('.').pop()}`,
  size: content.length,
  content,
});

const idsFor = (rel, content) => scanFile(file(rel, content)).map((f) => f.id);
const detects = (rel, content, id) => assert.ok(idsFor(rel, content).includes(id), `expected ${id}, got [${idsFor(rel, content)}]`);
const ignores = (rel, content, id) => assert.ok(!idsFor(rel, content).includes(id), `unexpected ${id} in ${rel}`);

console.log('\nDetection — true positives');

test('AWS access key', () => detects('src/a.js', "const k = 'AKIAIOSFODNN7EXAMPLE';", 'VG-SEC-001'));
test('Google/Gemini key', () => detects('src/a.js', "const k = 'AIzaSyD-1234567890abcdefghijklmnopqrstuv';", 'VG-SEC-002'));
test('OpenAI key', () => detects('src/a.js', "const k = 'sk-proj-abcdefghijklmnopqrstuvwxyz123456';", 'VG-SEC-003'));
test('GitHub token', () => detects('src/a.js', "const t = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';", 'VG-SEC-004'));
test('Private key block', () => detects('key.pem.js', '-----BEGIN RSA PRIVATE KEY-----', 'VG-SEC-006'));
test('DB URI with credentials', () => detects('src/db.js', "const u = 'postgres://admin:hunter2pass@db:5432/app';", 'VG-SEC-008'));
test('camelCase secret assignment', () => detects('src/a.js', "const jwtSecret = 'Kx9mQr2LpZ7vNw4Tb';", 'VG-SEC-009'));
test('client-exposed secret', () => detects('src/a.js', 'process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY', 'VG-SEC-010'));

test('SQL concatenation', () => detects('src/db.js', 'db.raw("SELECT * FROM u WHERE id=" + req.query.id);', 'VG-INJ-001'));
test('SQL template literal', () => detects('src/db.js', 'db.query(`SELECT * FROM u WHERE id = ${id}`);', 'VG-INJ-001'));
test('shell injection', () => detects('src/a.js', 'exec(`ls ${dir}`);', 'VG-INJ-002'));
test('python shell=True', () => detects('app.py', 'subprocess.run(cmd, shell=True)', 'VG-INJ-003'));
test('eval', () => detects('src/a.js', 'eval(userCode);', 'VG-INJ-004'));
test('pickle.loads', () => detects('app.py', 'data = pickle.loads(payload)', 'VG-INJ-005'));
test('NoSQL operator injection', () => detects('src/a.js', 'const u = await User.findOne(req.body);', 'VG-INJ-006'));

test('dangerouslySetInnerHTML', () => detects('src/a.jsx', '<div dangerouslySetInnerHTML={{ __html: comment }} />', 'VG-XSS-001'));
test('innerHTML from variable', () => detects('src/a.js', 'el.innerHTML = userBio;', 'VG-XSS-002'));
test('innerHTML interpolated', () => detects('src/a.js', 'el.innerHTML = `<b>${name}</b>`;', 'VG-XSS-002'));

test('wildcard CORS', () => detects('src/a.js', "res.setHeader('Access-Control-Allow-Origin', '*');", 'VG-CFG-001'));
test('TLS verification off', () => detects('src/a.js', 'const agent = { rejectUnauthorized: false };', 'VG-CFG-002'));
test('firestore public rules', () => detects('firestore.rules', 'allow read, write: if true;', 'VG-CFG-005'));

test('jwt.decode as auth', () => detects('src/a.js', 'const user = jwt.decode(token);', 'VG-AUT-001'));
test('md5 password hash', () => detects('src/a.js', "crypto.createHash('md5').update(pw);", 'VG-AUT-002'));
test('Math.random token', () => detects('src/a.js', 'const token = Math.random().toString(36);', 'VG-AUT-003'));
test('stubbed auth check', () => detects('src/a.js', 'const isAdmin = true;', 'VG-AUT-005'));

test('prompt interpolation', () => detects('src/a.js', 'const systemPrompt = `You are a bot. ${userInput}`;', 'VG-AI-001'));
test('LLM output to eval', () => detects('src/a.js', 'eval(response.message.content);', 'VG-AI-002'));
test('unauthenticated mutating route', () =>
  detects('src/api/reset.js', 'export async function POST(req) {\n  await db.deleteAll();\n}', 'VG-AI-003'));

console.log('\nDetection — false-positive control');

test('static innerHTML literal is safe', () =>
  ignores('src/a.js', 'btn.innerHTML = `<svg viewBox="0 0 24 24"></svg>`;', 'VG-XSS-002'));
test('SQL example in marketing HTML is skipped', () =>
  ignores('index.html', '<code>db.query(`SELECT * WHERE id = ${id}`)</code>', 'VG-INJ-001'));
test('placeholder credential is skipped', () =>
  ignores('src/a.js', "const password = 'your-password-here';", 'VG-SEC-009'));
test('env-var lookup is not a hardcoded secret', () =>
  ignores('src/a.js', 'const apiKey = process.env.OPENAI_API_KEY;', 'VG-SEC-009'));
test('.env.example is not flagged', () =>
  ignores('.env.example', 'API_KEY=Abcd1234EfghIjkl', 'VG-SEC-009'));
test('authenticated route is not flagged', () =>
  ignores('src/api/reset.js', 'export async function POST(req) {\n  const session = await getServerSession();\n  if (!session) return unauthorized();\n  await db.deleteAll();\n}', 'VG-AI-003'));
test('read-only route is not flagged', () =>
  ignores('src/api/list.js', 'export async function GET() {\n  return items;\n}', 'VG-AI-003'));
test('parameterised query is not flagged', () =>
  ignores('src/db.js', 'db.query("SELECT * FROM u WHERE id = $1", [id]);', 'VG-INJ-001'));

console.log('\nScoring and reporting');

test('clean project scores 100', () => assert.equal(scoreOf([], 20), 100));
test('one critical is severe but not zero', () => {
  const score = scoreOf([{ severity: 'CRITICAL' }], 20);
  assert.ok(score > 50 && score < 80, `got ${score}`);
});
test('many criticals bottom out', () =>
  assert.ok(scoreOf(Array(12).fill({ severity: 'CRITICAL' }), 20) < 15));
test('verdict labels track score', () => {
  assert.equal(verdictOf(100).label, 'STRONG');
  assert.equal(verdictOf(10).label, 'CRITICAL');
});
test('a quiet pattern-only scan is not called STRONG', () => {
  const v = verdictOf(100, false);
  assert.equal(v.label, 'INCOMPLETE');
  assert.equal(v.partial, true);
  assert.match(v.blurb, /not a clean bill of health/i);
});
test('pattern-only scan with findings keeps its severity label but flags coverage', () => {
  const v = verdictOf(30, false);
  assert.equal(v.label, 'DANGEROUS');
  assert.equal(v.partial, true);
  assert.match(v.blurb, /AI review did not run/i);
});
test('a scan with AI is never marked partial', () => {
  assert.equal(verdictOf(100, true).partial, undefined);
  assert.equal(verdictOf(30, true).partial, undefined);
});
test('dedupe collapses same file/line/category', () => {
  const a = { file: 'a.js', line: 3, category: 'Secrets', source: 'static', severity: 'HIGH' };
  const b = { file: 'a.js', line: 3, category: 'Secrets', source: 'gemini', severity: 'HIGH', description: 'x' };
  assert.equal(dedupe([a, b]).length, 1);
});
test('sort puts critical first', () => {
  const sorted = sortFindings([
    { severity: 'LOW', file: 'b.js', line: 1 },
    { severity: 'CRITICAL', file: 'a.js', line: 2 },
  ]);
  assert.equal(sorted[0].severity, 'CRITICAL');
});
test('markdown renders findings', () => {
  const md = buildMarkdown({
    findings: [{
      id: 'VG-SEC-001', title: 'Test finding', severity: 'CRITICAL', category: 'Secrets',
      cwe: 'CWE-798', file: 'src/a.js', line: 4, code: "const k='x'", description: 'Bad.',
      fix: 'Rotate it.', source: 'static',
    }],
    score: 40,
    stats: { filesScanned: 3, linesScanned: 90, durationMs: 1200 },
    meta: { target: '/tmp/app', scanTime: new Date().toISOString(), version: '2.0.0', model: null },
  });
  assert.ok(md.includes('# Security Audit Report'));
  assert.ok(md.includes('Test finding'));
  assert.ok(md.includes('src/a.js'));
  assert.ok(md.includes('Rotate it.'));
  assert.ok(md.includes('40/100'));
});
test('markdown handles zero findings with AI', () => {
  const md = buildMarkdown({
    findings: [], score: 100,
    stats: { filesScanned: 3, linesScanned: 90, durationMs: 10 },
    meta: { target: '/tmp/app', scanTime: new Date().toISOString(), version: '2.0.0', model: 'gemini-3.6-flash' },
  });
  assert.ok(md.includes('No vulnerabilities were identified'));
  assert.ok(!md.includes('AI review did not run'), 'must not warn when AI did run');
});
test('markdown warns loudly when AI did not run', () => {
  const md = buildMarkdown({
    findings: [], score: 100,
    stats: { filesScanned: 3, linesScanned: 90, durationMs: 10 },
    meta: { target: '/tmp/app', scanTime: new Date().toISOString(), version: '2.0.0', model: null },
  });
  assert.ok(md.includes('AI review did not run'), 'missing coverage warning');
  assert.ok(md.includes('[!WARNING]'), 'missing callout');
  assert.ok(!md.includes('100/100'), 'must not headline a perfect score on a half scan');
  assert.ok(md.includes('INCOMPLETE'));
});

console.log('\nGemini layer (offline)');

test('batching ranks risky files first', () => {
  const files = [
    file('README.js', 'const a = 1;\n'.repeat(50)),
    file('src/api/admin.js', 'export async function POST(req) { db.delete(req.body.id); }\n'.repeat(20)),
  ];
  const batches = buildBatches(files, [], 500_000);
  assert.ok(batches.length >= 1);
  assert.equal(batches[0][0].rel, 'src/api/admin.js');
});
test('batching respects the character budget', () => {
  const files = [file('src/api/a.js', 'req.body;\n'.repeat(20000))];
  const batches = buildBatches(files, [], 5_000);
  const total = batches.flat().reduce((n, f) => n + f.content.length, 0);
  assert.ok(total <= 20_000, `sent ${total} chars`);
});
test('error classification is actionable', () => {
  assert.equal(explainApiError({ status: 429, message: 'prepayment credits are depleted' }).kind, 'no-credit');
  assert.equal(explainApiError({ status: 400, message: 'API key not valid' }).kind, 'invalid-key');
  assert.equal(explainApiError({ status: 404, message: 'not found' }).kind, 'no-model');
  assert.equal(explainApiError({ status: 403, message: 'forbidden' }).kind, 'unauthorized');
});

console.log(`\n${failed === 0 ? 'PASS' : 'FAIL'} — ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
