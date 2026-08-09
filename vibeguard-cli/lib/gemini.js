// ============================================================
// VibeGuard — Gemini analysis layer
//
// Files are ranked by risk, batched into token-bounded requests, and sent to
// the Gemini API in parallel with structured-output JSON schemas so responses
// parse deterministically. Every failure mode degrades to "static-only"
// rather than aborting the scan.
// ============================================================

import { MODEL_FALLBACKS } from './config.js';

const ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models';

// Keep batches comfortably inside a fast response window.
const MAX_BATCH_CHARS = 48_000;
const MAX_FILE_CHARS = 16_000;

const RESPONSE_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'Exact relative path as given in the input header' },
          line: { type: 'integer', description: 'Line number of the vulnerable code' },
          title: { type: 'string', description: 'Short specific title, max 70 chars' },
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
          category: {
            type: 'string',
            enum: [
              'Secrets', 'Injection', 'XSS', 'Access Control', 'Authentication',
              'Cryptography', 'Misconfiguration', 'LLM Security', 'Supply Chain',
              'Data Exposure', 'Denial of Service', 'Business Logic',
            ],
          },
          cwe: { type: 'string', description: 'CWE identifier, e.g. CWE-89' },
          code: { type: 'string', description: 'The vulnerable line(s), verbatim, max 200 chars' },
          description: { type: 'string', description: 'What the flaw is and how it is exploited, 2-4 sentences' },
          fix: { type: 'string', description: 'Concrete remediation with the corrected pattern' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
        required: ['file', 'line', 'title', 'severity', 'category', 'description', 'fix', 'confidence'],
      },
    },
  },
  required: ['findings'],
};

const SYSTEM_PROMPT = `You are VibeGuard, a precise application-security auditor reviewing AI-generated ("vibe-coded") code.

Report only vulnerabilities you can point to in the supplied code. For each one, name the exact file and line, explain the concrete exploit path, and give a fix a developer can apply directly.

Weight your attention toward the failure modes AI-written code actually exhibits:
- Endpoints that mutate data with no authentication or ownership check.
- Authorization checks that exist but are trivially bypassable, stubbed, or left as TODO.
- Secrets hardcoded in source, or server secrets leaked into client bundles via NEXT_PUBLIC_/VITE_/REACT_APP_ prefixes.
- User input reaching SQL, shell, filesystem paths, deserializers, or the DOM without validation.
- Prompt injection: user text concatenated into LLM instructions, and model output flowing into a dangerous sink.
- Insecure defaults copied from tutorials: wildcard CORS, disabled TLS verification, permissive database rules, debug mode on.
- Missing rate limiting or ownership checks on expensive or destructive operations.
- Broken object-level authorization: an ID taken from the request and used without verifying it belongs to the caller.

Rules:
- Do NOT report style issues, missing tests, performance, or generic "consider adding X" advice.
- Do NOT invent line numbers. Use the numbers shown in the left gutter of each file.
- Do NOT repeat the same issue for every occurrence; report the clearest instance.
- If a construct is safe in context (parameterised query, validated input, server-only file), stay silent.
- Set confidence to "low" when you cannot see the surrounding call site, and reserve CRITICAL for issues that are directly exploitable by an unauthenticated attacker.
- If nothing qualifies, return an empty findings array.`;

function numberLines(content) {
  const lines = content.split(/\r?\n/);
  const width = String(lines.length).length;
  return lines.map((line, i) => `${String(i + 1).padStart(width)} | ${line}`).join('\n');
}

/**
 * Rank files so the AI budget is spent where risk concentrates.
 * Static findings are the strongest signal; path and content heuristics follow.
 */
function riskScore(file, staticFindings) {
  let score = 0;
  const hits = staticFindings.filter((f) => f.file === file.rel);
  for (const hit of hits) {
    score += hit.severity === 'CRITICAL' ? 40 : hit.severity === 'HIGH' ? 25 : 10;
  }

  const rel = file.rel.toLowerCase();
  if (/(^|\/)(api|routes?|controllers?|handlers?|server|actions?|middleware)\//.test(rel)) score += 30;
  if (/(auth|login|session|token|admin|payment|billing|checkout|upload|user)/.test(rel)) score += 25;
  if (/(config|settings|env)/.test(rel)) score += 15;
  if (/\.(sql|tf|rules)$/.test(rel) || /dockerfile/i.test(file.name)) score += 15;

  const content = file.content;
  if (/\b(req|request)\.(body|query|params|headers)\b/.test(content)) score += 20;
  if (/\b(prompt|systemInstruction|openai|anthropic|generateContent|chat\.completions)\b/i.test(content)) score += 20;
  if (/\b(exec|eval|innerHTML|query|raw|readFile|writeFile)\s*\(/.test(content)) score += 15;
  if (/(password|secret|token|api[_-]?key)/i.test(content)) score += 10;

  // Slight preference for mid-size files: tiny files rarely hold logic.
  if (file.size > 400) score += 5;

  return score;
}

/** Group ranked files into request-sized batches. */
export function buildBatches(files, staticFindings, budgetChars) {
  const ranked = files
    .map((file) => ({ file, score: riskScore(file, staticFindings) }))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score);

  const batches = [];
  let current = [];
  let currentChars = 0;
  let spent = 0;

  for (const { file } of ranked) {
    if (spent >= budgetChars) break;

    const content =
      file.content.length > MAX_FILE_CHARS
        ? `${file.content.slice(0, MAX_FILE_CHARS)}\n… (truncated)`
        : file.content;
    const cost = content.length;

    if (currentChars + cost > MAX_BATCH_CHARS && current.length) {
      batches.push(current);
      current = [];
      currentChars = 0;
    }

    current.push({ rel: file.rel, content });
    currentChars += cost;
    spent += cost;
  }

  if (current.length) batches.push(current);
  return batches;
}

function batchToPrompt(batch) {
  const body = batch
    .map((f) => `### FILE: ${f.rel}\n\`\`\`\n${numberLines(f.content)}\n\`\`\``)
    .join('\n\n');
  return `Audit the following files for security vulnerabilities.\n\n${body}`;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function callGemini({ apiKey, model, prompt, signal, timeoutMs = 90_000 }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  if (signal) signal.addEventListener('abort', () => controller.abort(), { once: true });

  try {
    const res = await fetch(`${ENDPOINT}/${model}:generateContent?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,
          responseMimeType: 'application/json',
          responseSchema: RESPONSE_SCHEMA,
          maxOutputTokens: 8192,
        },
        safetySettings: [
          'HARM_CATEGORY_HARASSMENT',
          'HARM_CATEGORY_HATE_SPEECH',
          'HARM_CATEGORY_SEXUALLY_EXPLICIT',
          'HARM_CATEGORY_DANGEROUS_CONTENT',
        ].map((category) => ({ category, threshold: 'BLOCK_NONE' })),
      }),
    });

    const text = await res.text();
    if (!res.ok) {
      let message = text.slice(0, 400);
      try {
        message = JSON.parse(text)?.error?.message ?? message;
      } catch {
        /* keep raw */
      }
      const err = new Error(message);
      err.status = res.status;
      throw err;
    }

    const data = JSON.parse(text);
    const parts = data?.candidates?.[0]?.content?.parts ?? [];
    const payload = parts.map((p) => p.text ?? '').join('');
    if (!payload.trim()) return [];

    const parsed = JSON.parse(payload);
    return Array.isArray(parsed.findings) ? parsed.findings : [];
  } finally {
    clearTimeout(timer);
  }
}

/** Classify an API error into something the user can act on. */
export function explainApiError(err) {
  const msg = String(err?.message ?? err);
  const status = err?.status;

  if (status === 400 && /API key not valid/i.test(msg)) {
    return {
      kind: 'invalid-key',
      summary: 'The Gemini API key was rejected as invalid.',
      action: 'Create a new key at https://aistudio.google.com/apikey and run `vibeguard auth <key>`.',
    };
  }
  if (status === 401 || status === 403) {
    return {
      kind: 'unauthorized',
      summary: 'The Gemini API key is not authorized for this model or the API is not enabled on the project.',
      action: 'Enable the Generative Language API on the project, or issue a fresh key at https://aistudio.google.com/apikey.',
    };
  }
  if (status === 429 && /prepay|credit|billing/i.test(msg)) {
    return {
      kind: 'no-credit',
      summary: 'The key is valid but the Google Cloud project has no remaining Gemini credit.',
      action: 'Top up prepaid credits or enable billing at https://ai.studio/projects, or issue a key on a project with free-tier quota. Scans still run on the pattern engine.',
    };
  }
  if (status === 429) {
    return {
      kind: 'rate-limited',
      summary: 'Gemini rate limit or quota exhausted for this key.',
      action: 'Wait for the quota window to reset, lower --concurrency, or use a key on a billed project.',
    };
  }
  if (status === 404) {
    return {
      kind: 'no-model',
      summary: 'The requested Gemini model is not available to this key.',
      action: 'Pass a different model with --model (for example `gemini-2.5-flash`).',
    };
  }
  if (/abort/i.test(msg)) {
    return { kind: 'timeout', summary: 'The Gemini request timed out.', action: 'Re-run, or reduce --ai-budget to send smaller batches.' };
  }
  return { kind: 'error', summary: `Gemini request failed: ${msg}`, action: 'Re-run with --no-ai to skip the AI pass.' };
}

/**
 * Run the AI pass. Never throws — returns { findings, model, error, batches }.
 * `onProgress(done, total)` fires as batches complete.
 */
export async function analyzeWithGemini({
  files,
  staticFindings,
  apiKey,
  model,
  concurrency = 4,
  budgetChars = 400_000,
  onProgress = () => {},
}) {
  const batches = buildBatches(files, staticFindings, budgetChars);
  if (!batches.length) return { findings: [], model, error: null, batches: 0 };

  // Resolve the model once, on the first batch, so a bad model name fails fast
  // and we can fall back without burning every batch.
  const candidates = [model, ...MODEL_FALLBACKS.filter((m) => m !== model)];
  let activeModel = null;
  let firstResult = null;
  let fatal = null;

  for (const candidate of candidates) {
    try {
      firstResult = await callGemini({ apiKey, model: candidate, prompt: batchToPrompt(batches[0]) });
      activeModel = candidate;
      break;
    } catch (err) {
      const info = explainApiError(err);
      if (info.kind === 'no-model') continue; // try the next model
      fatal = { err, info };
      break;
    }
  }

  if (!activeModel) {
    const info = fatal?.info ?? explainApiError({ status: 404, message: 'no model available' });
    return { findings: [], model: null, error: info, batches: batches.length };
  }

  const findings = [...firstResult];
  let done = 1;
  onProgress(done, batches.length);

  const remaining = batches.slice(1);
  let cursor = 0;
  let softError = null;

  const worker = async () => {
    while (cursor < remaining.length) {
      const batch = remaining[cursor++];
      const prompt = batchToPrompt(batch);

      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          findings.push(...(await callGemini({ apiKey, model: activeModel, prompt })));
          break;
        } catch (err) {
          const retryable = err.status === 429 || err.status === 503 || /abort/i.test(String(err.message));
          if (!retryable || attempt === 2) {
            softError = softError ?? explainApiError(err);
            break;
          }
          await sleep(700 * Math.pow(2, attempt) + Math.random() * 300);
        }
      }

      onProgress(++done, batches.length);
    }
  };

  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(concurrency, remaining.length || 1)) }, worker)
  );

  return {
    findings: normalize(findings, files),
    model: activeModel,
    error: softError,
    batches: batches.length,
  };
}

/** Validate AI output against reality: real paths, in-range lines, sane fields. */
function normalize(raw, files) {
  const byPath = new Map(files.map((f) => [f.rel, f]));
  const out = [];
  let counter = 1;

  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const file = byPath.get(item.file);
    if (!file) continue; // hallucinated path — drop it

    const fileLines = file.content.split(/\r?\n/);
    // Ignore the empty element a trailing newline produces, so a clamped line
    // still points at real code.
    if (fileLines.length > 1 && fileLines[fileLines.length - 1] === '') fileLines.pop();

    const line = Number.isInteger(item.line) ? Math.min(Math.max(1, item.line), fileLines.length) : 1;
    const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(item.severity) ? item.severity : 'MEDIUM';
    const actualLine = fileLines[line - 1] ?? '';

    out.push({
      id: `VG-AI-${String(counter++).padStart(3, '0')}`,
      title: String(item.title || 'Unnamed finding').slice(0, 120),
      severity,
      category: item.category || 'Business Logic',
      cwe: item.cwe || null,
      file: item.file,
      line,
      code: (item.code || actualLine).trim().slice(0, 220),
      description: String(item.description || '').trim(),
      fix: String(item.fix || '').trim(),
      confidence: ['high', 'medium', 'low'].includes(item.confidence) ? item.confidence : 'medium',
      source: 'gemini',
    });
  }

  return out;
}

/** Cheap liveness/credential probe used by `vibeguard doctor`. */
export async function probeKey(apiKey) {
  try {
    const res = await fetch(`${ENDPOINT}?key=${encodeURIComponent(apiKey)}&pageSize=200`);
    const text = await res.text();
    if (!res.ok) {
      const err = new Error(JSON.parse(text)?.error?.message ?? text.slice(0, 300));
      err.status = res.status;
      throw err;
    }
    const models = (JSON.parse(text).models ?? [])
      .filter((m) => (m.supportedGenerationMethods ?? []).includes('generateContent'))
      .map((m) => m.name.replace('models/', ''));
    return { ok: true, models };
  } catch (err) {
    return { ok: false, error: explainApiError(err) };
  }
}

/** Confirm the key can actually generate, not merely authenticate. */
export async function probeGeneration(apiKey, model) {
  try {
    await callGemini({
      apiKey,
      model,
      prompt: 'Return an empty findings array.',
      timeoutMs: 20_000,
    });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: explainApiError(err) };
  }
}
