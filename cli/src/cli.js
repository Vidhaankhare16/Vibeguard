// ============================================================
// VibeSec CLI — Command definitions
// ============================================================

import { Command } from 'commander';
import { runScan } from './commands/scan.js';
import { showVersion } from './commands/version.js';

export function createCLI(argv) {
  const program = new Command();

  program
    .name('vibesec')
    .description('Extraordinary security audit for AI-generated apps')
    .version('0.1.0', '-v, --version', 'Print version number')
    .addHelpText('after', `
Examples:
  $ npx vibesec scan .
  $ npx vibesec scan ./my-app
  $ npx vibesec scan . --output json
  $ npx vibesec scan . --output html
    `);

  // scan command
  program
    .command('scan [path]')
    .description('Run a full security audit on a project directory')
    .option('-o, --output <format>', 'Output format: terminal | json | html', 'terminal')
    .option('--no-git', 'Skip git history scanning')
    .option('--no-deps', 'Skip dependency verification')
    .option('--severity <level>', 'Minimum severity to report: critical | high | medium | low', 'low')
    .action((targetPath, options) => {
      runScan(targetPath || '.', options);
    });

  // version command (explicit)
  program
    .command('version')
    .description('Print version information')
    .action(showVersion);

  program.parse(argv);
}
