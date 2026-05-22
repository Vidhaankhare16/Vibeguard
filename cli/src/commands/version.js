// ============================================================
// VibeSec CLI — version command
// ============================================================

import chalk from 'chalk';

export function showVersion() {
  console.log('');
  console.log(chalk.cyan.bold('  ⚡ vibesec') + chalk.white(' v0.1.0'));
  console.log(chalk.dim('  https://vibesec.dev'));
  console.log('');
}
