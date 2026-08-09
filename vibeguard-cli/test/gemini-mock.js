// ============================================================
// VibeGuard — Gemini transport test against a stubbed API
//
// Exercises the request shape, response parsing, hallucination filtering and
// error handling without spending a token.
//   node test/gemini-mock.js
// ============================================================

import assert from 'node:assert/strict';
import { analyzeWithGemini } from '../lib/gemini.js';

let passed = 0;
let failed = 0;
const check = (name, fn) => {
  try {
    fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL ${name}\n       ${err.message.split('\n')[0]}`);
  }
};

const FILES = [
  {
    rel: 'src/api/admin.js',
    name: 'admin.js',
    ext: '.js',
    size: 90,
    content: 'export async function POST(req) {\n  await db.delete(req.body.id);\n}\n',
  },
];

const ok = (payload) => ({
  ok: true,
  status: 200,
  text: async () => JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(payload) }] } }] }),
});

const err = (status, message) => ({
  ok: false,
  status,
  text: async () => JSON.stringify({ error: { message, code: status } }),
});

const originalFetch = globalThis.fetch;

// ---------------------------------------------------------------- happy path

console.log('\nGemini transport — successful response');

let seenPrompt = null;
let seenBody = null;
let calls = 0;

globalThis.fetch = async (_url, init) => {
  calls++;
  seenBody = JSON.parse(init.body);
  seenPrompt = seenBody.contents[0].parts[0].text;
  return ok({
    findings: [
      {
        file: 'src/api/admin.js', line: 2, title: 'No ownership check on delete',
        severity: 'CRITICAL', category: 'Access Control', cwe: 'CWE-639',
        code: 'db.delete(req.body.id)', description: 'Any user can delete any record.',
        fix: 'Verify the record belongs to the session user.', confidence: 'high',
      },
      // Hallucinated file — must be discarded.
      { file: 'does/not/exist.js', line: 5, title: 'Ghost', severity: 'HIGH', category: 'Injection', description: 'x', fix: 'y', confidence: 'low' },
      // Line past end of file — must be clamped.
      { file: 'src/api/admin.js', line: 99999, title: 'Out of range', severity: 'LOW', category: 'Misconfiguration', description: 'x', fix: 'y', confidence: 'low' },
      // Unknown severity — must default rather than crash.
      { file: 'src/api/admin.js', line: 1, title: 'Odd severity', severity: 'SPICY', category: 'Injection', description: 'x', fix: 'y', confidence: 'nope' },
    ],
  });
};

const result = await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 'test', model: 'gemini-3.6-flash' });

check('one request per batch', () => assert.equal(calls, 1));
check('system instruction is sent', () => assert.ok(seenBody.systemInstruction.parts[0].text.includes('VibeGuard')));
check('structured output requested', () => assert.equal(seenBody.generationConfig.responseMimeType, 'application/json'));
check('response schema attached', () => assert.ok(seenBody.generationConfig.responseSchema.properties.findings));
check('risky file included in prompt', () => assert.ok(seenPrompt.includes('src/api/admin.js')));
check('prompt carries line numbers', () => assert.ok(/^\s*\d+ \|/m.test(seenPrompt)));
check('model resolved on first try', () => assert.equal(result.model, 'gemini-3.6-flash'));
check('no error reported', () => assert.equal(result.error, null));
check('hallucinated file discarded', () => assert.ok(!result.findings.some((f) => f.file === 'does/not/exist.js')));
check('out-of-range line clamped', () => assert.equal(result.findings.find((f) => f.title === 'Out of range').line, 3));
check('unknown severity defaults to MEDIUM', () => assert.equal(result.findings.find((f) => f.title === 'Odd severity').severity, 'MEDIUM'));
check('unknown confidence defaults to medium', () => assert.equal(result.findings.find((f) => f.title === 'Odd severity').confidence, 'medium'));
check('findings tagged as gemini', () => assert.ok(result.findings.every((f) => f.source === 'gemini')));
check('ids assigned', () => assert.ok(result.findings.every((f) => f.id.startsWith('VG-AI-'))));

// ------------------------------------------------- empty-result confirmation

console.log('\nGemini transport — empty-result confirmation');

// Sampling means an empty response is unreliable; a quiet batch must be
// re-asked before the tool reports "no issues found".
const REAL = {
  file: 'src/api/admin.js', line: 2, title: 'Missed on the first sample',
  severity: 'HIGH', category: 'Access Control', description: 'x', fix: 'y', confidence: 'high',
};

let n = 0;
globalThis.fetch = async () => ok({ findings: n++ === 0 ? [] : [REAL] });
const recovered = await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 't', model: 'gemini-3.6-flash' });
check('empty first sample is re-asked', () => assert.equal(n, 2));
check('finding recovered on the second sample', () => assert.equal(recovered.findings.length, 1));

n = 0;
globalThis.fetch = async () => { n++; return ok({ findings: [] }); };
const genuinelyClean = await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 't', model: 'gemini-3.6-flash' });
check('two empties are believed', () => assert.equal(n, 2));
check('genuinely clean stays clean', () => assert.deepEqual(genuinelyClean.findings, []));

n = 0;
globalThis.fetch = async () => { n++; return ok({ findings: [REAL] }); };
await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 't', model: 'gemini-3.6-flash' });
check('a productive batch is not re-sent', () => assert.equal(n, 1));

// ---------------------------------------------------------------- fallbacks

console.log('\nGemini transport — failure handling');

let attempts = [];
globalThis.fetch = async (url) => {
  const model = String(url).match(/models\/([^:]+):/)[1];
  attempts.push(model);
  if (model === 'gemini-3.6-flash') return err(404, 'model not found');
  return ok({ findings: [] });
};
const fellBack = await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 'test', model: 'gemini-3.6-flash' });
check('falls back when model is unavailable', () => {
  assert.equal(attempts[0], 'gemini-3.6-flash');
  assert.ok(fellBack.model && fellBack.model !== 'gemini-3.6-flash', `fell back to ${fellBack.model}`);
});

globalThis.fetch = async () => err(429, 'Your prepayment credits are depleted.');
const noCredit = await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 'test', model: 'gemini-3.6-flash' });
check('depleted credit surfaces, does not throw', () => {
  assert.equal(noCredit.model, null);
  assert.equal(noCredit.error.kind, 'no-credit');
  assert.deepEqual(noCredit.findings, []);
});

globalThis.fetch = async () => err(400, 'API key not valid. Please pass a valid API key.');
const badKey = await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 'bad', model: 'gemini-3.6-flash' });
check('invalid key surfaces, does not throw', () => assert.equal(badKey.error.kind, 'invalid-key'));

globalThis.fetch = async () => { throw new Error('getaddrinfo ENOTFOUND'); };
const offline = await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 'test', model: 'gemini-3.6-flash' });
check('network failure degrades gracefully', () => {
  assert.equal(offline.model, null);
  assert.deepEqual(offline.findings, []);
});

globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => 'not json at all' });
const garbage = await analyzeWithGemini({ files: FILES, staticFindings: [], apiKey: 'test', model: 'gemini-3.6-flash' });
check('malformed response degrades gracefully', () => assert.deepEqual(garbage.findings, []));

globalThis.fetch = originalFetch;

console.log(`\n${failed === 0 ? 'PASS' : 'FAIL'} — ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
