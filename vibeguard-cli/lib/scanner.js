import readline from 'readline';
import { 
  RESET, BOLD, DIM, CYAN, GREEN, YELLOW, RED, BRIGHT_CYAN, BRIGHT_GREEN, BRIGHT_RED, BRIGHT_YELLOW, HR 
} from './ascii.js';

// Wait utility
export const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Prompt utility using Node built-in readline
export const promptQuestion = (query) => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => {
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
};

// Rich Interactive Spinner
export const runSpinner = async (message, duration = 1500) => {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let i = 0;
  const start = Date.now();
  
  process.stdout.write(`  ${CYAN}${frames[0]}${RESET}  ${message}`);
  
  while (Date.now() - start < duration) {
    await wait(80);
    i = (i + 1) % frames.length;
    readline.cursorTo(process.stdout, 0);
    process.stdout.write(`  ${CYAN}${frames[i]}${RESET}  ${message}`);
  }
  
  readline.cursorTo(process.stdout, 0);
  // Clear the line completely
  process.stdout.write(' '.repeat(process.stdout.columns || 80) + '\r');
};

// Log levels
export const logSuccess = (message) => console.log(`  ${GREEN}✔${RESET}  ${message}`);
export const logWarning = (message) => console.log(`  ${YELLOW}⚠${RESET}  ${message}`);
export const logError = (message) => console.log(`  ${RED}✘${RESET}  ${message}`);
export const logStep = (message) => console.log(`\n${BOLD}${CYAN}»${RESET} ${BOLD}${message}${RESET}`);

// Sample scanned vulnerabilities to return
export const getSampleVulnerabilities = () => [
  {
    id: "VG-001",
    title: "AI-Hallucinated Package Dependency",
    severity: "CRITICAL",
    category: "AI Supply Chain",
    file: "package.json",
    line: 14,
    description: "Detected dependency on 'react-auth-vibe-helper'. This package does not exist on npm registry (or was registered <2 hours ago with 0 historical downloads). LLMs frequently hallucinate helper utilities. Attackers monitor these hallucinations to register malicious packages.",
    code: `"react-auth-vibe-helper": "^1.0.4"`,
    fix: "Remove the hallucinated dependency immediately. Rewrite the logic using standard libraries like 'next-auth' or 'lucia'."
  },
  {
    id: "VG-002",
    title: "Endpoint Authorization Bypass (Shadow API Route)",
    severity: "HIGH",
    category: "Access Control",
    file: "src/pages/api/admin/system-reset.ts",
    line: 4,
    description: "API route does not contain any token verification or authentication middleware. The route performs database mutation operations and is publicly callable by external anonymous requests. AI code assistants often focus on modular file completion and omit top-level authorization guards.",
    code: `export default async function handler(req, res) {\n  if (req.method === 'POST') {\n    await db.truncateAllTables();\n    res.status(200).json({ success: true });\n  }\n}`,
    fix: "Wrap the api handler in your auth guard helper (e.g., 'withAdminAuth(...)') before exporting."
  },
  {
    id: "VG-003",
    title: "Unsanitized AI Prompt Injection Path",
    severity: "MEDIUM",
    category: "LLM Security",
    file: "src/app/actions/chat.ts",
    line: 22,
    description: "User input is directly interpolated into the system prompt message without escaping or length validation. Allows prompt injection to override application behavior or exfiltrate environment variables.",
    code: `const systemPrompt = \`Analyze this user query: \${userInput} and format the answer.\`;`,
    fix: "Ensure user inputs are mapped as separate 'user' role messages, or sanitized through boundary validation schemas."
  },
  {
    id: "VG-004",
    title: "Wildcard CORS and Hardcoded Dev Key Leakage",
    severity: "HIGH",
    category: "Insecure Defaults",
    file: "src/config/openai.js",
    line: 8,
    description: "CORS is configured to allow all origins ('*') alongside a hardcoded development API key prefix 'sk-proj-vibeTest123...'. Standard behavior for AI generators trying to make front-end and back-end integration 'just work' during setup.",
    code: `headers: { 'Access-Control-Allow-Origin': '*' },\nconst apiKey = 'sk-proj-vibeTest123XYZ99808381';`,
    fix: "Remove the hardcoded secret and replace with 'process.env.OPENAI_API_KEY'. Tighten CORS headers to target specific domain lists."
  }
];

// Interactive survey for setting up the scan
export const setupScanParams = async () => {
  const isNonInteractive = process.argv.includes('-y') || process.argv.includes('--yes') || process.argv.includes('--non-interactive');

  if (isNonInteractive) {
    console.log(`\n  ${DIM}Running in non-interactive mode (using defaults)...${RESET}`);
    console.log(`  ${BOLD}Scan targets:${RESET} JavaScript, TypeScript, package.json, config files`);
    console.log(`  ${BOLD}Audit level:${RESET} Extraordinarily Defensive`);
    console.log(`  ${BOLD}Audit Depth:${RESET} Deep Audit (Static Analysis + AI Auditor Simulation)`);
    return { targetPath: '.', depth: '2' };
  }

  console.log(`\n${BOLD}Please configure your audit params:${RESET}\n`);
  
  let targetPath = await promptQuestion(`  ${BOLD}Enter target directory to audit [default: .]:${RESET} `);
  if (!targetPath) targetPath = '.';
  
  console.log(`\n  ${BOLD}Select Audit Depth:${RESET}`);
  console.log(`    ${CYAN}1)${RESET} Fast Scan (Static Heuristics only)`);
  console.log(`    ${CYAN}2)${RESET} Deep Audit (Static Analysis + AI Auditor Simulation) [Recommended]`);
  console.log(`    ${CYAN}3)${RESET} Full Suite (Static + Dynamic Local Sandbox + AI Audit)`);
  
  let depth = await promptQuestion(`\n  ${BOLD}Choose option [1-3, default: 2]:${RESET} `);
  if (!depth || !['1', '2', '3'].includes(depth)) depth = '2';
  
  console.log(`\n  ${BOLD}Scan targets:${RESET} JavaScript, TypeScript, package.json, config files`);
  console.log(`  ${BOLD}Audit level:${RESET} Extraordinarily Defensive`);
  
  const proceed = await promptQuestion(`\n  ${BRIGHT_GREEN}${BOLD}Start security run-through? (Y/n):${RESET} `);
  if (proceed.toLowerCase() === 'n') {
    console.log(`\n  ${RED}Audit cancelled.${RESET}\n`);
    process.exit(0);
  }
  
  return { targetPath, depth };
};
