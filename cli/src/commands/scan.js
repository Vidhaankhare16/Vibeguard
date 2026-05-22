// ============================================================
// VibeSec CLI — scan command
// This is a scaffold. Full analysis engine coming soon.
// ============================================================

import chalk from 'chalk';
import ora from 'ora';
import path from 'path';
import fs from 'fs';

const VIBESEC_VERSION = '0.1.0';

// ASCII banner
function printBanner() {
  console.log('');
  console.log(chalk.cyan.bold('  ⚡ vibesec') + chalk.dim(` v${VIBESEC_VERSION}`));
  console.log(chalk.dim('  Security audit for AI-generated apps'));
  console.log('');
}

// Resolve and validate the target path
function resolvePath(targetPath) {
  const resolved = path.resolve(process.cwd(), targetPath);
  if (!fs.existsSync(resolved)) {
    console.error(chalk.red(`  ✗ Path not found: ${resolved}`));
    process.exit(1);
  }
  return resolved;
}

// Planned scan layers — these will be implemented in future versions
const SCAN_LAYERS = [
  { id: 'ai-patterns',    label: 'AI-specific vulnerability patterns' },
  { id: 'taint',          label: 'Cross-file taint analysis' },
  { id: 'auth',           label: 'Authorization & access control' },
  { id: 'injection',      label: 'Injection vulnerabilities' },
  { id: 'secrets',        label: 'Secrets in codebase' },
  { id: 'git-history',    label: 'Git history secrets' },
  { id: 'auth-session',   label: 'Authentication & session security' },
  { id: 'data-exposure',  label: 'Data exposure' },
  { id: 'misconfig',      label: 'Security misconfiguration' },
  { id: 'client-side',    label: 'Client-side vulnerabilities' },
  { id: 'infra',          label: 'Infrastructure & deployment' },
  { id: 'supply-chain',   label: 'Supply chain & dependencies' },
];

// Simulate a scan step with a spinner (scaffold — no real analysis yet)
async function simulateStep(label, durationMs) {
  return new Promise(resolve => setTimeout(resolve, durationMs));
}

export async function runScan(targetPath, options) {
  printBanner();

  const resolved = resolvePath(targetPath);
  const displayPath = path.relative(process.cwd(), resolved) || '.';

  console.log(chalk.dim(`  Target: `) + chalk.white(displayPath));
  console.log(chalk.dim(`  Output: `) + chalk.white(options.output));
  console.log('');

  // ── Coming soon notice ──────────────────────────────────────
  console.log(
    chalk.bgCyan.black.bold('  EARLY ACCESS  ') +
    chalk.dim('  Full analysis engine is under active development.')
  );
  console.log('');
  console.log(chalk.dim('  VibeSec will perform the following checks when ready:'));
  console.log('');

  SCAN_LAYERS.forEach((layer, i) => {
    const num = String(i + 1).padStart(2, '0');
    console.log(
      chalk.dim(`  ${num}  `) +
      chalk.white(layer.label)
    );
  });

  console.log('');
  console.log(chalk.dim('  ─────────────────────────────────────────────────────'));
  console.log('');

  // Show a preview spinner sequence so the UX feels real
  const spinner = ora({
    text: chalk.dim('Initializing scanner...'),
    color: 'cyan',
    indent: 2,
  }).start();

  await simulateStep('init', 600);
  spinner.text = chalk.dim('Detecting project type...');

  await simulateStep('detect', 500);

  // Detect basic project info
  const projectInfo = detectProject(resolved);
  spinner.text = chalk.dim(`Detected: ${projectInfo.type}`);

  await simulateStep('scan', 800);
  spinner.succeed(chalk.dim(`Project detected: `) + chalk.cyan(projectInfo.type));

  console.log('');
  console.log(
    chalk.yellow('  ⚠  Full scan engine coming soon.')
  );
  console.log('');
  console.log(
    chalk.dim('  Star the repo to get notified when v1.0 ships:')
  );
  console.log(
    chalk.cyan('  https://github.com/vibesec/vibesec')
  );
  console.log('');
  console.log(
    chalk.dim('  Read about what VibeSec will check:')
  );
  console.log(
    chalk.cyan('  https://vibesec.dev')
  );
  console.log('');
}

// Basic project type detection — will be expanded in v1
function detectProject(dirPath) {
  const files = fs.readdirSync(dirPath).map(f => f.toLowerCase());

  if (files.includes('package.json')) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(dirPath, 'package.json'), 'utf8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps['next']) return { type: 'Next.js' };
      if (deps['nuxt'] || deps['nuxt3']) return { type: 'Nuxt.js' };
      if (deps['@sveltejs/kit']) return { type: 'SvelteKit' };
      if (deps['express']) return { type: 'Express.js' };
      if (deps['fastify']) return { type: 'Fastify' };
      if (deps['react']) return { type: 'React' };
      if (deps['vue']) return { type: 'Vue.js' };

      return { type: 'Node.js' };
    } catch {
      return { type: 'Node.js' };
    }
  }

  if (files.includes('requirements.txt') || files.includes('pyproject.toml')) {
    return { type: 'Python' };
  }

  if (files.includes('go.mod')) return { type: 'Go' };
  if (files.includes('cargo.toml')) return { type: 'Rust' };
  if (files.includes('pom.xml') || files.includes('build.gradle')) return { type: 'Java' };
  if (files.includes('composer.json')) return { type: 'PHP' };

  return { type: 'Unknown project' };
}
