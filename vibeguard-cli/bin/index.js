#!/usr/bin/env node
// ============================================================
// VibeGuard CLI
// ============================================================

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { Command } from 'commander';

import { collectFiles, readFiles } from '../lib/walk.js';
import { scanAll, sortFindings, dedupe, scoreOf, verdictOf } from '../lib/rules.js';
import { analyzeWithGemini, probeKey, probeGeneration } from '../lib/gemini.js';
import { writeReports, printSummary, MD_FILENAME } from '../lib/report.js';
import {
  resolveApiKey, resolveModel, writeConfig, maskKey, CONFIG_FILE, DEFAULT_MODEL,
} from '../lib/config.js';
import { banner, log, createSpinner, BOLD, DIM, RESET, CYAN, YELLOW, GREEN, RED } from '../lib/ui.js';

const VERSION = '2.0.1';
const program = new Command();

program
  .name('vibeguard')
  .description('Gemini-powered security auditing for AI-generated code')
  .version(VERSION, '-v, --version')
  .addHelpText(
    'after',
    `
Examples:
  $ vibeguard auth <your-gemini-api-key>   Save a Gemini key for future scans
  $ vibeguard scan .                       Audit the current directory
  $ vibeguard scan ./my-app                Audit another folder (report lands there)
  $ vibeguard scan . --no-ai               Pattern engine only, no API calls
  $ vibeguard scan . --fail-on high        Exit non-zero on high+ findings (CI)
  $ vibeguard doctor                       Check key, quota and available models

Get a free Gemini API key at https://aistudio.google.com/apikey
`
  );

// ------------------------------------------------------------------ scan

program
  .command('scan [path]', { isDefault: true })
  .description('Audit a directory for security vulnerabilities and write a Markdown report into it')
  .option('-k, --key <key>', 'Gemini API key (overrides env and saved config)')
  .option('-m, --model <model>', `Gemini model to use (default: ${DEFAULT_MODEL})`)
  .option('--no-ai', 'Skip the Gemini pass and run the pattern engine only')
  .option('--no-json', 'Write only the Markdown report')
  .option('-o, --output <file>', `Markdown report filename (default: ${MD_FILENAME})`)
  .option('-c, --concurrency <n>', 'Parallel Gemini requests', '4')
  .option('--ai-budget <chars>', 'Max characters of source sent to Gemini', '400000')
  .option('--max-files <n>', 'Stop discovery after N files', '4000')
  .option('--fail-on <severity>', 'Exit 1 if a finding at or above this severity exists (critical|high|medium|low)')
  .option('--quiet', 'Suppress the banner and per-finding output')
  .action(runScan);

// ------------------------------------------------------------------ auth

program
  .command('auth [key]')
  .description('Save a Gemini API key to ~/.vibeguard/config.json')
  .option('-m, --model <model>', 'Also set the default model')
  .action(async (key, options) => {
    if (!key && !options.model) {
      const { key: existing, source } = resolveApiKey(null);
      if (existing) {
        log.ok(`A key is already configured: ${BOLD}${maskKey(existing)}${RESET} ${DIM}(from ${source})${RESET}`);
      } else {
        log.warn('No Gemini API key configured.');
      }
      log.plain('');
      log.info(`Usage: ${CYAN}vibeguard auth <your-api-key>${RESET}`);
      log.info(`Get one free at ${CYAN}https://aistudio.google.com/apikey${RESET}`);
      return;
    }

    const patch = {};
    if (key) patch.apiKey = key;
    if (options.model) patch.model = options.model;
    const file = writeConfig(patch);

    if (key) {
      const spinner = createSpinner('Verifying key with the Gemini API…');
      const probe = await probeKey(key);
      if (probe.ok) {
        spinner.succeed(`Key verified — ${probe.models.length} models available.`);
      } else {
        spinner.warn(`Key saved, but verification failed: ${probe.error.summary}`);
        log.detail(probe.error.action);
      }
    }
    log.ok(`Saved to ${CYAN}${file}${RESET}`);
  });

// ------------------------------------------------------------------ doctor

program
  .command('doctor')
  .description('Check that the API key, quota and models are healthy')
  .option('-k, --key <key>', 'Key to test instead of the configured one')
  .option('-m, --model <model>', 'Model to test generation against')
  .action(async (options) => {
    banner(VERSION);
    let failed = false;

    log.step('Environment');
    const nodeMajor = Number(process.versions.node.split('.')[0]);
    if (nodeMajor >= 18) {
      log.ok(`Node.js ${process.versions.node}`);
    } else {
      log.error(`Node.js ${process.versions.node} — VibeGuard needs >= 18 (global fetch).`);
      failed = true;
    }

    log.step('API key');
    const { key, source } = resolveApiKey(options.key);
    if (!key) {
      log.error('No Gemini API key found.');
      log.detail(`Checked: --key flag, GEMINI_API_KEY, GOOGLE_API_KEY, ./.env, ${CONFIG_FILE}`);
      log.detail('Get a free key at https://aistudio.google.com/apikey then run `vibeguard auth <key>`.');
      log.plain('');
      log.warn('Scans will still run, using the pattern engine only.');
      process.exitCode = 1;
      return;
    }
    log.ok(`Found ${BOLD}${maskKey(key)}${RESET} ${DIM}(from ${source})${RESET}`);

    log.step('Authentication');
    const authSpinner = createSpinner('Listing available models…');
    const probe = await probeKey(key);
    if (!probe.ok) {
      authSpinner.fail(probe.error.summary);
      log.detail(probe.error.action);
      process.exitCode = 1;
      return;
    }
    authSpinner.succeed(`Key authenticates. ${probe.models.length} models support generateContent.`);

    const model = resolveModel(options.model);
    const available = probe.models.includes(model);
    if (available) {
      log.ok(`Configured model ${BOLD}${model}${RESET} is available.`);
    } else {
      log.warn(`Configured model ${BOLD}${model}${RESET} is not in this key's model list.`);
      log.detail(`Available flash models: ${probe.models.filter((m) => m.includes('flash')).slice(0, 6).join(', ')}`);
      failed = true;
    }

    log.step('Generation quota');
    const genSpinner = createSpinner(`Sending a test request to ${model}…`);
    const gen = await probeGeneration(key, available ? model : probe.models[0]);
    if (gen.ok) {
      genSpinner.succeed('Generation works — AI-assisted scanning is fully enabled.');
    } else {
      genSpinner.fail(gen.error.summary);
      log.detail(gen.error.action);
      failed = true;
    }

    log.plain('');
    if (failed) {
      log.warn('VibeGuard will run, but the AI pass is degraded — see above.');
      process.exitCode = 1;
    } else {
      log.ok(`${GREEN}${BOLD}Everything checks out.${RESET}`);
    }
    log.plain('');
  });

program.parseAsync(process.argv);

// ------------------------------------------------------------------ runner

async function runScan(targetPath, options) {
  const started = Date.now();
  const quiet = Boolean(options.quiet);
  if (!quiet) banner(VERSION);

  // ---- resolve target
  const target = path.resolve(process.cwd(), targetPath || '.');
  if (!fs.existsSync(target)) {
    log.error(`Path not found: ${target}`);
    process.exit(2);
  }
  if (!fs.statSync(target).isDirectory()) {
    log.error(`Not a directory: ${target}`);
    process.exit(2);
  }
  if (isDangerousRoot(target)) {
    log.error(`Refusing to scan ${target} — point VibeGuard at a project folder, not a filesystem or home root.`);
    process.exit(2);
  }

  log.info(`Auditing ${BOLD}${target}${RESET}`);

  // ---- discovery
  const discover = createSpinner('Discovering source files…');
  const { files: descriptors, skipped, truncated } = await collectFiles(target, {
    maxFiles: Number(options.maxFiles) || 4000,
  });
  const files = await readFiles(descriptors);
  const linesScanned = files.reduce((n, f) => n + f.content.split('\n').length, 0);

  if (!files.length) {
    discover.warn('No source files found to analyse.');
    log.detail('VibeGuard reads code and config files; empty or fully-ignored directories yield nothing.');
    process.exit(0);
  }
  discover.succeed(
    `Read ${BOLD}${files.length}${RESET} files ${DIM}(${linesScanned.toLocaleString()} lines)${RESET}`
  );
  if (truncated) log.detail(`File limit reached — raise it with --max-files.`);
  if (skipped.oversized) log.detail(`${skipped.oversized} oversized file(s) skipped.`);

  // ---- static pass
  const staticSpinner = createSpinner('Running pattern analysis…');
  const staticFindings = scanAll(files);
  staticSpinner.succeed(
    staticFindings.length
      ? `Pattern analysis found ${BOLD}${staticFindings.length}${RESET} issue(s)`
      : 'Pattern analysis found no issues'
  );

  // ---- AI pass
  let aiFindings = [];
  let usedModel = null;

  if (options.ai === false) {
    log.info(`${DIM}AI review skipped (--no-ai).${RESET}`);
  } else {
    const { key, source } = resolveApiKey(options.key, target);
    if (!key) {
      log.warn('No Gemini API key — running pattern analysis only.');
      log.detail('The AI pass adds what patterns cannot see: authorization gaps, broken');
      log.detail('ownership checks, and logic flaws specific to your code.');
      log.detail(`Enable it once:  ${CYAN}vibeguard auth <key>${RESET}   ${DIM}free key: https://aistudio.google.com/apikey${RESET}`);
      log.detail(`Or silence this:  ${CYAN}vibeguard scan . --no-ai${RESET}`);
    } else {
      const model = resolveModel(options.model);
      const aiSpinner = createSpinner(`Gemini reviewing high-risk files with ${model}…`);

      const result = await analyzeWithGemini({
        files,
        staticFindings,
        apiKey: key,
        model,
        concurrency: Math.max(1, Number(options.concurrency) || 4),
        budgetChars: Math.max(10_000, Number(options.aiBudget) || 400_000),
        onProgress: (done, total) =>
          aiSpinner.update(`Gemini reviewing high-risk files… ${DIM}batch ${done}/${total}${RESET}`),
      });

      if (result.model) {
        usedModel = result.model;
        aiFindings = result.findings;
        aiSpinner.succeed(
          aiFindings.length
            ? `Gemini review found ${BOLD}${aiFindings.length}${RESET} additional issue(s) ${DIM}(${result.batches} batch${result.batches === 1 ? '' : 'es'}, ${result.model})${RESET}`
            : `Gemini review found no additional issues ${DIM}(${result.model})${RESET}`
        );
        if (result.error) {
          log.warn(`Some batches failed: ${result.error.summary}`);
          log.detail(result.error.action);
        }
      } else {
        aiSpinner.fail(result.error.summary);
        log.detail(result.error.action);
        log.detail(`Key in use: ${maskKey(key)} (from ${source})`);
        log.warn('Continuing with pattern analysis only.');
      }
    }
  }

  // ---- merge, score, report
  const findings = sortFindings(dedupe([...staticFindings, ...aiFindings]));
  const score = scoreOf(findings, files.length);
  const durationMs = Date.now() - started;

  const written = writeReports({
    targetDir: target,
    findings,
    score,
    stats: { filesScanned: files.length, linesScanned, durationMs },
    json: options.json !== false,
    meta: {
      version: VERSION,
      scanTime: new Date().toISOString(),
      target,
      model: usedModel,
      mdFilename: options.output,
    },
  });

  if (quiet) {
    console.log(`${score}/100 ${verdictOf(score).label} — ${findings.length} finding(s) — ${written[0]}`);
  } else {
    printSummary({ findings, score, stats: { filesScanned: files.length }, written, targetDir: target });
    log.plain(`  ${DIM}Completed in ${(durationMs / 1000).toFixed(1)}s${RESET}\n`);
  }

  // ---- exit code
  if (options.failOn) {
    const threshold = String(options.failOn).toUpperCase();
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    if (!(threshold in order)) {
      log.error(`Unknown --fail-on value "${options.failOn}". Use critical, high, medium or low.`);
      process.exit(2);
    }
    const breached = findings.some((f) => (order[f.severity] ?? 9) <= order[threshold]);
    if (breached) {
      log.error(`Findings at or above ${threshold} — failing the build.`);
      process.exit(1);
    }
  }
}

function isDangerousRoot(dir) {
  const resolved = path.resolve(dir);
  const home = process.env.HOME || process.env.USERPROFILE;
  if (path.parse(resolved).root === resolved) return true;
  if (home && path.resolve(home) === resolved) return true;
  return false;
}
