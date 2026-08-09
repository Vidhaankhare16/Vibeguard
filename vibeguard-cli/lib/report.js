// ============================================================
// VibeGuard — report generation
//
// Writes the Markdown report (and optional JSON) INTO the scanned directory,
// so `vibeguard scan ./some/app` leaves its findings next to the code.
// ============================================================

import fs from 'node:fs';
import path from 'node:path';
import { SEVERITY_ORDER, verdictOf } from './rules.js';
import {
  BOLD, DIM, RESET, CYAN, GREEN, RED, YELLOW, BRIGHT_GREEN, BRIGHT_RED,
  BRIGHT_YELLOW, severityBadge, severityColor,
} from './ui.js';

export const MD_FILENAME = 'SECURITY-REPORT.md';
export const JSON_FILENAME = 'vibeguard-report.json';

const SEVERITY_EMOJI = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵',
};

const LANG_BY_EXT = {
  '.js': 'javascript', '.jsx': 'jsx', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'tsx', '.py': 'python', '.rb': 'ruby',
  '.php': 'php', '.go': 'go', '.java': 'java', '.cs': 'csharp', '.rs': 'rust',
  '.sh': 'bash', '.bash': 'bash', '.sql': 'sql', '.yml': 'yaml', '.yaml': 'yaml',
  '.json': 'json', '.tf': 'hcl', '.html': 'html', '.vue': 'vue', '.svelte': 'svelte',
};

const langOf = (file) => LANG_BY_EXT[path.extname(file).toLowerCase()] ?? 'text';

export function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    if (f.severity in counts) counts[f.severity]++;
  }
  return counts;
}

function groupByFile(findings) {
  const map = new Map();
  for (const f of findings) {
    if (!map.has(f.file)) map.set(f.file, []);
    map.get(f.file).push(f);
  }
  return [...map.entries()].sort((a, b) => {
    const worst = (list) => Math.min(...list.map((f) => SEVERITY_ORDER[f.severity] ?? 9));
    return worst(a[1]) - worst(b[1]) || a[0].localeCompare(b[0]);
  });
}

// ------------------------------------------------------------------ markdown

export function buildMarkdown({ findings, score, stats, meta }) {
  const counts = countBySeverity(findings);
  const aiRan = Boolean(meta.model);
  const verdict = verdictOf(score, aiRan);
  const total = findings.length;
  const grouped = groupByFile(findings);

  const lines = [];
  const push = (...xs) => lines.push(...xs);

  push('# Security Audit Report');
  push('');
  push(`**Directory scanned:** \`${meta.target}\`  `);
  push(`**Generated:** ${new Date(meta.scanTime).toUTCString()}  `);
  push(`**Engine:** VibeGuard v${meta.version}${meta.model ? ` + Gemini (\`${meta.model}\`)` : ' (static analysis only)'}  `);
  push(`**Files analysed:** ${stats.filesScanned} (${stats.linesScanned.toLocaleString()} lines) in ${(stats.durationMs / 1000).toFixed(1)}s`);
  push('');
  push('---');
  push('');

  // ---- verdict block
  // A score is meaningful when findings exist. It is only misleading in the
  // one case where a half-run scan found nothing — so drop it there alone.
  push(
    verdict.partial && total === 0
      ? `## Verdict: ${verdict.label} — pattern analysis only`
      : `## Verdict: ${score}/100 — ${verdict.label}`
  );
  push('');
  push(`> ${verdict.blurb}`);
  push('');

  if (!aiRan) {
    push('> [!WARNING]');
    push('> **AI review did not run for this scan.** The pattern engine matches known-bad');
    push('> code shapes; it cannot reason about whether a record belongs to the caller,');
    push('> whether a balance check is atomic, or whether a request body is over-trusted.');
    push('> Enable the AI pass with `vibeguard auth <key>` (free key:');
    push('> https://aistudio.google.com/apikey) and re-scan for full coverage.');
    push('');
  }

  if (total === 0) {
    push(
      aiRan
        ? 'No vulnerabilities were identified in this scan.'
        : 'Nothing matched the pattern rules. That is not the same as being secure — see the warning above.'
    );
    push('');
    push('A clean result is not proof of safety. It means nothing was found in the files');
    push('that were analysed. Re-scan after significant changes, and keep dependency');
    push('auditing (`npm audit`) in your pipeline.');
    push('');
    return lines.join('\n');
  }

  // ---- summary table
  push('### Findings by severity');
  push('');
  push('| Severity | Count | What it means |');
  push('| :--- | ---: | :--- |');
  push(`| ${SEVERITY_EMOJI.CRITICAL} **Critical** | ${counts.CRITICAL} | Directly exploitable by an anonymous attacker. Fix before deploying. |`);
  push(`| ${SEVERITY_EMOJI.HIGH} **High** | ${counts.HIGH} | Exploitable with modest effort or a low-privilege account. |`);
  push(`| ${SEVERITY_EMOJI.MEDIUM} **Medium** | ${counts.MEDIUM} | Weakens defences or enables a larger attack chain. |`);
  push(`| ${SEVERITY_EMOJI.LOW} **Low** | ${counts.LOW} | Hardening opportunity; low immediate risk. |`);
  push(`| | **${total}** | **total** |`);
  push('');

  // ---- priority queue
  const urgent = findings
    .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 8);

  if (urgent.length) {
    push('### Fix these first');
    push('');
    urgent.forEach((f, i) => {
      push(`${i + 1}. **${f.title}** — \`${f.file}:${f.line}\`  `);
      push(`   ${f.fix}`);
    });
    push('');
  }

  push('### Affected files');
  push('');
  push('| File | Findings | Highest severity |');
  push('| :--- | ---: | :--- |');
  for (const [file, list] of grouped) {
    const worst = list.reduce((acc, f) =>
      (SEVERITY_ORDER[f.severity] ?? 9) < (SEVERITY_ORDER[acc] ?? 9) ? f.severity : acc,
    'LOW');
    push(`| \`${file}\` | ${list.length} | ${SEVERITY_EMOJI[worst] ?? ''} ${worst} |`);
  }
  push('');
  push('---');
  push('');

  // ---- detail
  push('## Detailed findings');
  push('');

  let index = 0;
  for (const [file, list] of grouped) {
    push(`### \`${file}\``);
    push('');
    for (const f of list) {
      index++;
      push(`#### ${index}. ${f.title}`);
      push('');
      push(
        `${SEVERITY_EMOJI[f.severity] ?? ''} **${f.severity}** ` +
          `&nbsp;·&nbsp; ${f.category}` +
          (f.cwe ? ` &nbsp;·&nbsp; [${f.cwe}](https://cwe.mitre.org/data/definitions/${String(f.cwe).replace(/\D/g, '')}.html)` : '') +
          ` &nbsp;·&nbsp; line ${f.line}` +
          (f.source === 'gemini' ? ` &nbsp;·&nbsp; _AI review${f.confidence ? `, ${f.confidence} confidence` : ''}_` : '')
      );
      push('');
      push(f.description);
      push('');
      if (f.code) {
        push(`\`\`\`${langOf(f.file)}`);
        push(`// ${f.file}:${f.line}`);
        push(f.code);
        push('```');
        push('');
      }
      push(`**Fix**`);
      push('');
      push(f.fix);
      push('');
    }
    push('---');
    push('');
  }

  // ---- footer
  push('## Notes on this report');
  push('');
  push('- Findings marked _AI review_ come from a Gemini pass over the highest-risk files; they catch logic and authorization flaws that pattern matching cannot, but should be confirmed against the surrounding code.');
  push('- Unmarked findings come from VibeGuard\'s pattern engine and are deterministic.');
  push('- Any credential named here must be treated as compromised and rotated — removing it from the working tree does not remove it from git history.');
  push('- A clean scan is not a security guarantee. This tool does not replace dependency auditing, penetration testing, or code review.');
  push('');
  push(`<sub>Generated by [VibeGuard](https://github.com/Vidhaankhare16/Vibeguard) v${meta.version} · \`npx @vidhaankhare/vibeguard scan .\`</sub>`);
  push('');

  return lines.join('\n');
}

export function writeReports({ targetDir, findings, score, stats, meta, json = true }) {
  const written = [];

  const mdPath = path.join(targetDir, meta.mdFilename ?? MD_FILENAME);
  fs.writeFileSync(mdPath, buildMarkdown({ findings, score, stats, meta }), 'utf8');
  written.push(mdPath);

  if (json) {
    const jsonPath = path.join(targetDir, JSON_FILENAME);
    fs.writeFileSync(
      jsonPath,
      `${JSON.stringify(
        {
          version: meta.version,
          scanTime: meta.scanTime,
          targetDirectory: targetDir,
          engine: { static: true, ai: Boolean(meta.model), model: meta.model ?? null },
          durationMs: stats.durationMs,
          filesScanned: stats.filesScanned,
          linesScanned: stats.linesScanned,
          securityScore: score,
          verdict: verdictOf(score, Boolean(meta.model)).label,
          coverage: meta.model ? 'static+ai' : 'static-only',
          vulnerabilityCounts: countBySeverity(findings),
          vulnerabilities: findings,
        },
        null,
        2
      )}\n`,
      'utf8'
    );
    written.push(jsonPath);
  }

  return written;
}

// ------------------------------------------------------------------ terminal

export function printSummary({ findings, score, stats, written, targetDir, aiRan = true }) {
  const counts = countBySeverity(findings);
  const verdict = verdictOf(score, aiRan);
  const scoreColor = verdict.partial ? BRIGHT_YELLOW : score >= 75 ? BRIGHT_GREEN : score >= 50 ? BRIGHT_YELLOW : BRIGHT_RED;

  console.log('');
  if (verdict.partial && findings.length === 0) {
    // No score at all here — a number is exactly what would mislead.
    console.log(`  ${BOLD}Result${RESET}  ${scoreColor}${BOLD}${verdict.label}${RESET} ${DIM}·${RESET} ${DIM}pattern analysis only${RESET}`);
  } else {
    console.log(`  ${BOLD}Security score${RESET}  ${scoreColor}${BOLD}${score}/100${RESET} ${DIM}·${RESET} ${scoreColor}${verdict.label}${RESET}`);
  }
  console.log(`  ${DIM}${verdict.blurb}${RESET}`);
  console.log('');

  if (findings.length === 0) {
    console.log(
      aiRan
        ? `  ${GREEN}No vulnerabilities found across ${stats.filesScanned} files.${RESET}`
        : `  ${YELLOW}Nothing matched the pattern rules across ${stats.filesScanned} files.${RESET}\n  ${DIM}Logic and authorization flaws need the AI pass — they were not checked.${RESET}`
    );
  } else {
    const parts = [];
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      if (counts[severity]) {
        parts.push(`${severityColor(severity)}${BOLD}${counts[severity]}${RESET} ${severityColor(severity)}${severity.toLowerCase()}${RESET}`);
      }
    }
    console.log(`  ${BOLD}${findings.length}${RESET} finding${findings.length === 1 ? '' : 's'}:  ${parts.join(`  ${DIM}|${RESET}  `)}`);
    console.log('');

    const top = findings.slice(0, 6);
    for (const f of top) {
      console.log(`  ${severityBadge(f.severity)} ${f.title}`);
      console.log(`           ${DIM}${f.file}:${f.line}${RESET}`);
    }
    if (findings.length > top.length) {
      console.log(`  ${DIM}… and ${findings.length - top.length} more in the report.${RESET}`);
    }
  }

  console.log('');
  for (const file of written) {
    // Show whichever form is shorter — a relative path that climbs out of the
    // tree is worse than just printing the absolute one.
    const rel = path.relative(process.cwd(), file);
    const display = rel && rel.length < file.length && !rel.startsWith('..' + path.sep + '..') ? rel : file;
    console.log(`  ${GREEN}→${RESET} ${CYAN}${display}${RESET}`);
  }
  console.log('');
}
