// ============================================================
// VibeGuard — file discovery
//
// Concurrent directory walk that skips vendored/build output and binaries,
// honours .gitignore-style directory names, and caps per-file size so a
// stray 50MB bundle can't stall a scan.
// ============================================================

import fs from 'node:fs/promises';
import path from 'node:path';

export const IGNORED_DIRS = new Set([
  '.git', '.hg', '.svn',
  'node_modules', 'bower_components', 'jspm_packages',
  'dist', 'build', 'out', 'output', '.next', '.nuxt', '.svelte-kit', '.astro',
  '.output', '.vercel', '.netlify', '.serverless',
  'coverage', '.nyc_output',
  'vendor', 'venv', '.venv', 'env', '__pycache__', '.mypy_cache', '.pytest_cache',
  '.cache', '.parcel-cache', '.turbo', '.gradle', 'target',
  '.idea', '.vscode', '.terraform',
  'Pods', 'DerivedData',
]);

// Extensions we read as source. Anything else is skipped outright.
const SOURCE_EXTS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts',
  '.vue', '.svelte', '.astro',
  '.py', '.rb', '.php', '.go', '.java', '.kt', '.kts', '.cs', '.rs', '.swift',
  '.c', '.h', '.cpp', '.hpp', '.m', '.mm', '.scala', '.ex', '.exs', '.dart',
  '.sh', '.bash', '.zsh', '.ps1',
  '.sql', '.graphql', '.gql',
  '.json', '.yml', '.yaml', '.toml', '.ini', '.conf', '.cfg', '.properties',
  '.tf', '.tfvars', '.hcl',
  '.html', '.htm', '.ejs', '.hbs', '.pug',
  '.env', '.rules', '.xml', '.gradle',
]);

// Extension-less files that still matter.
const SOURCE_BASENAMES = new Set([
  'Dockerfile', 'dockerfile', 'Procfile', 'Makefile',
  '.env', '.env.local', '.env.development', '.env.production', '.env.example',
  '.npmrc', '.dockerignore', '.htaccess',
]);

// Files that are technically source but almost never worth AI tokens.
const LOW_VALUE = /(\.min\.(js|css)|\.lock|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|\.map)$/i;

// VibeGuard's own output. Without this, a second scan re-reports every finding
// quoted in the previous report's code snippets.
const SELF_ARTIFACT = /^(vibeguard-report\.(json|md)|SECURITY-REPORT\.md|vibeguard-report\.html)$/i;

export const DEFAULT_MAX_FILE_BYTES = 512 * 1024; // 512 KB
export const DEFAULT_MAX_FILES = 4000;

function isSourceFile(name) {
  if (SOURCE_BASENAMES.has(name)) return true;
  if (name.startsWith('.env')) return true;
  const ext = path.extname(name).toLowerCase();
  return SOURCE_EXTS.has(ext);
}

/**
 * Walk `root`, returning file descriptors: { abs, rel, size, ext, name }.
 * Directory entries are read concurrently, breadth-first.
 */
export async function collectFiles(root, opts = {}) {
  const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
  const maxBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const extraIgnores = new Set(opts.ignore ?? []);

  const files = [];
  const skipped = { oversized: 0, binary: 0 };
  let queue = [root];
  let truncated = false;

  while (queue.length && !truncated) {
    const batch = queue;
    queue = [];

    const results = await Promise.all(
      batch.map(async (dir) => {
        try {
          return { dir, entries: await fs.readdir(dir, { withFileTypes: true }) };
        } catch {
          return { dir, entries: [] };
        }
      })
    );

    for (const { dir, entries } of results) {
      for (const entry of entries) {
        const abs = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (IGNORED_DIRS.has(entry.name) || extraIgnores.has(entry.name)) continue;
          queue.push(abs);
          continue;
        }
        if (!entry.isFile()) continue;
        if (!isSourceFile(entry.name)) continue;
        if (LOW_VALUE.test(entry.name)) continue;
        if (SELF_ARTIFACT.test(entry.name)) continue;

        let stat;
        try {
          stat = await fs.stat(abs);
        } catch {
          continue;
        }
        if (stat.size > maxBytes) {
          skipped.oversized++;
          continue;
        }

        files.push({
          abs,
          rel: path.relative(root, abs).split(path.sep).join('/'),
          size: stat.size,
          name: entry.name,
          ext: path.extname(entry.name).toLowerCase(),
        });

        if (files.length >= maxFiles) {
          truncated = true;
          break;
        }
      }
      if (truncated) break;
    }
  }

  return { files, skipped, truncated };
}

/** Read file contents with bounded concurrency. Adds `.content` in place. */
export async function readFiles(files, concurrency = 32) {
  let cursor = 0;
  const out = [];

  const worker = async () => {
    while (cursor < files.length) {
      const file = files[cursor++];
      try {
        const content = await fs.readFile(file.abs, 'utf8');
        // Cheap binary sniff — a NUL byte near the top means it is not text.
        if (content.slice(0, 8192).includes(String.fromCharCode(0))) continue;
        out.push({ ...file, content });
      } catch {
        /* unreadable — skip */
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, files.length || 1) }, worker));
  // Stable order so reports are deterministic.
  out.sort((a, b) => a.rel.localeCompare(b.rel));
  return out;
}
