// Colors and formatting using ANSI Escape Codes
const ESC = '\u001b[';
export const RESET = `${ESC}0m`;
export const BOLD = `${ESC}1m`;
export const DIM = `${ESC}2m`;
export const ITALIC = `${ESC}3m`;
export const UNDERLINE = `${ESC}4m`;

// Foreground colors
export const CYAN = `${ESC}36m`;
export const MAGENTA = `${ESC}35m`;
export const BLUE = `${ESC}34m`;
export const YELLOW = `${ESC}33m`;
export const GREEN = `${ESC}32m`;
export const RED = `${ESC}31m`;
export const WHITE = `${ESC}37m`;

// Bright Foreground colors
export const BRIGHT_CYAN = `${ESC}96m`;
export const BRIGHT_MAGENTA = `${ESC}95m`;
export const BRIGHT_GREEN = `${ESC}92m`;
export const BRIGHT_RED = `${ESC}91m`;
export const BRIGHT_YELLOW = `${ESC}93m`;

// Background colors
export const BG_RED = `${ESC}41m`;
export const BG_GREEN = `${ESC}42m`;
export const BG_YELLOW = `${ESC}43m`;
export const BG_BLUE = `${ESC}44m`;
export const BG_MAGENTA = `${ESC}45m`;
export const BG_CYAN = `${ESC}46m`;

export const BANNER = `
${BRIGHT_CYAN}${BOLD} ██╗   ██╗██╗██████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
 ██║   ██║██║██╔══██╗██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ╚██╗ ██╔╝██║██████╔╝█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ╚████╔╝ ██║██╔══██╗██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ╚██╔╝  ██║██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝   ╚═╝╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
${RESET}
               ${BG_MAGENTA}${WHITE}${BOLD}  V I B E   G U A R D  ${RESET}  ${DIM}•  Zero-Trust AI Code Auditor v1.0.0${RESET}
`;

export const HR = `${DIM}────────────────────────────────────────────────────────────────────────────────${RESET}`;

export const renderHeader = () => {
  console.clear();
  console.log(BANNER);
  console.log(HR);
  console.log(` ${BRIGHT_CYAN}▶${RESET} Ready to audit vibe-coded repository at: ${BOLD}${process.cwd()}${RESET}`);
  console.log(HR);
};
