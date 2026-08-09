// ============================================================
// VibeGuard — API key + settings resolution
//
// Resolution order (first hit wins):
//   1. --key flag
//   2. GEMINI_API_KEY / GOOGLE_API_KEY env var
//   3. .env file in the current working directory
//   4. ~/.vibeguard/config.json  (written by `vibeguard auth`)
//
// The key is never written into the repo — only into the user's home dir.
// ============================================================

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export const CONFIG_DIR = path.join(os.homedir(), '.vibeguard');
export const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

export const DEFAULT_MODEL = 'gemini-3.6-flash';

// Tried in order when the requested model is unavailable to this key.
export const MODEL_FALLBACKS = [
  'gemini-3.6-flash',
  'gemini-3.5-flash',
  'gemini-flash-latest',
  'gemini-2.5-flash',
];

export function readConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return {};
  }
}

export function writeConfig(patch) {
  const merged = { ...readConfig(), ...patch };
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(merged, null, 2), 'utf8');
  // Best-effort tighten permissions (no-op on most Windows filesystems).
  try {
    fs.chmodSync(CONFIG_FILE, 0o600);
  } catch {
    /* ignore */
  }
  return CONFIG_FILE;
}

// Minimal .env reader — only pulls the two keys we care about, no side effects
// on process.env beyond what we return.
function readDotEnv(dir) {
  const file = path.join(dir, '.env');
  try {
    const text = fs.readFileSync(file, 'utf8');
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      const name = line.slice(0, eq).trim().replace(/^export\s+/, '');
      if (name !== 'GEMINI_API_KEY' && name !== 'GOOGLE_API_KEY') continue;
      const value = line
        .slice(eq + 1)
        .trim()
        .replace(/^['"]|['"]$/g, '');
      if (value) return value;
    }
  } catch {
    /* no .env, or unreadable */
  }
  return null;
}

export function resolveApiKey(cliKey, cwd = process.cwd()) {
  if (cliKey) return { key: cliKey, source: '--key flag' };

  if (process.env.GEMINI_API_KEY) {
    return { key: process.env.GEMINI_API_KEY, source: 'GEMINI_API_KEY env var' };
  }
  if (process.env.GOOGLE_API_KEY) {
    return { key: process.env.GOOGLE_API_KEY, source: 'GOOGLE_API_KEY env var' };
  }

  const fromEnvFile = readDotEnv(cwd);
  if (fromEnvFile) return { key: fromEnvFile, source: '.env file' };

  const cfg = readConfig();
  if (cfg.apiKey) return { key: cfg.apiKey, source: CONFIG_FILE };

  return { key: null, source: null };
}

export function resolveModel(cliModel) {
  return cliModel || process.env.VIBEGUARD_MODEL || readConfig().model || DEFAULT_MODEL;
}

export function maskKey(key) {
  if (!key) return '(none)';
  if (key.length <= 12) return `${key.slice(0, 3)}…`;
  return `${key.slice(0, 6)}…${key.slice(-4)}`;
}
