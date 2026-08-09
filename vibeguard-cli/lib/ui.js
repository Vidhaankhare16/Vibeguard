// ============================================================
// VibeGuard — terminal output
//
// Colour is gated on TTY + NO_COLOR. The spinner repaints a single line and
// degrades to plain status lines when output is piped, so CI logs stay clean.
// ============================================================

import process from 'node:process';

const supportsColor =
  process.stdout.isTTY &&
  !process.env.NO_COLOR &&
  process.env.TERM !== 'dumb';

const ESC = String.fromCharCode(27) + '[';
const wrap = (code) => (supportsColor ? `${ESC}${code}m` : '');

export const RESET = wrap(0);
export const BOLD = wrap(1);
export const DIM = wrap(2);
export const CYAN = wrap(36);
export const MAGENTA = wrap(35);
export const YELLOW = wrap(33);
export const GREEN = wrap(32);
export const RED = wrap(31);
export const WHITE = wrap(37);
export const BRIGHT_CYAN = wrap(96);
export const BRIGHT_GREEN = wrap(92);
export const BRIGHT_RED = wrap(91);
export const BRIGHT_YELLOW = wrap(93);
export const BG_MAGENTA = wrap(45);

export const isTTY = Boolean(process.stdout.isTTY);

const useUnicode = process.platform !== 'win32' || Boolean(process.env.WT_SESSION) || process.env.TERM_PROGRAM === 'vscode';

const GLYPH = {
  ok: useUnicode ? '✔' : '+',
  warn: useUnicode ? '▲' : '!',
  err: useUnicode ? '✘' : 'x',
  arrow: useUnicode ? '›' : '>',
  bullet: useUnicode ? '•' : '-',
};

export function banner(version) {
  const art = `${BRIGHT_CYAN}${BOLD}
  ██╗   ██╗██╗██████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██║   ██║██║██╔══██╗██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ╚██╗ ██╔╝██║██████╔╝█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ╚████╔╝ ██║██╔══██╗██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ╚██╔╝  ██║██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
     ╚═╝   ╚═╝╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝${RESET}`;

  if (!useUnicode || !isTTY) {
    console.log(`\n  ${BOLD}${BRIGHT_CYAN}VIBEGUARD${RESET} ${DIM}v${version} — AI-native security auditor${RESET}\n`);
    return;
  }
  console.log(art);
  console.log(`  ${DIM}v${version} ${GLYPH.bullet} Gemini-powered security auditing for AI-generated code${RESET}\n`);
}

export const log = {
  info: (msg) => console.log(`  ${DIM}${GLYPH.bullet}${RESET} ${msg}`),
  ok: (msg) => console.log(`  ${GREEN}${GLYPH.ok}${RESET} ${msg}`),
  warn: (msg) => console.log(`  ${YELLOW}${GLYPH.warn}${RESET} ${msg}`),
  error: (msg) => console.log(`  ${RED}${GLYPH.err}${RESET} ${msg}`),
  step: (msg) => console.log(`\n${BOLD}${CYAN}${GLYPH.arrow}${RESET} ${BOLD}${msg}${RESET}`),
  plain: (msg = '') => console.log(msg),
  detail: (msg) => console.log(`    ${DIM}${msg}${RESET}`),
};

const FRAMES = useUnicode
  ? ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
  : ['-', '\\', '|', '/'];

/**
 * A spinner tied to real work: `spinner.update()` changes the label mid-flight,
 * and `succeed`/`fail` stop it with a final line. No artificial delay anywhere.
 */
export function createSpinner(label) {
  let text = label;
  let timer = null;
  let frame = 0;
  const start = Date.now();

  const clear = () => {
    if (!isTTY) return;
    process.stdout.write(`\r${' '.repeat(Math.max(0, (process.stdout.columns || 80) - 1))}\r`);
  };

  const render = () => {
    clear();
    const line = `  ${CYAN}${FRAMES[frame]}${RESET} ${text}`;
    const max = (process.stdout.columns || 80) - 2;
    process.stdout.write(line.length > max + 20 ? `${line.slice(0, max + 20)}…` : line);
    frame = (frame + 1) % FRAMES.length;
  };

  if (isTTY) {
    render();
    timer = setInterval(render, 80);
    if (timer.unref) timer.unref();
  } else {
    console.log(`  ... ${text}`);
  }

  const stop = (glyph, color, finalText) => {
    if (timer) clearInterval(timer);
    timer = null;
    clear();
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    console.log(`  ${color}${glyph}${RESET} ${finalText ?? text} ${DIM}(${elapsed}s)${RESET}`);
  };

  return {
    update(next) {
      text = next;
      if (!isTTY) return;
      render();
    },
    succeed: (finalText) => stop(GLYPH.ok, GREEN, finalText),
    warn: (finalText) => stop(GLYPH.warn, YELLOW, finalText),
    fail: (finalText) => stop(GLYPH.err, RED, finalText),
    stop: () => {
      if (timer) clearInterval(timer);
      timer = null;
      clear();
    },
  };
}

export const severityColor = (severity) =>
  ({ CRITICAL: BRIGHT_RED, HIGH: RED, MEDIUM: YELLOW, LOW: CYAN }[severity] ?? DIM);

export const severityBadge = (severity) => {
  const pad = severity.padEnd(8);
  return `${severityColor(severity)}${BOLD}${pad}${RESET}`;
};
