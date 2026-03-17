#!/usr/bin/env node

// PreToolUse hook for Bash: blocks commands that try to inspect env vars or read .env files.
// Exit code 2 = block the command. Exit code 0 = allow.

const BLOCKED_PATTERNS = [
  // direct env inspection
  /\bprintenv\b/,
  /\benv\b(?:\s|$|\s*\|)/,
  /\bexport\s+-p\b/,
  /\bdeclare\s+-x\b/,
  /\bcompgen\s+-v\b/,
  /\bset\b(?:\s*$|\s*\|)/,

  // reading .env files
  /\bcat\s+[^\|]*\.env/,
  /\bless\s+[^\|]*\.env/,
  /\bmore\s+[^\|]*\.env/,
  /\bhead\s+[^\|]*\.env/,
  /\btail\s+[^\|]*\.env/,
  /\bsource\s+[^\|]*\.env/,
  /\.\s+[^\|]*\.env/,

  // echoing env vars that look like secrets
  /\becho\s+.*\$[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY)/i,
  /\bprintf\s+.*\$[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY)/i,

  // grep/search for secrets in env
  /\benv\s*\|\s*grep/,
  /\bprintenv\s*\|\s*grep/,

  // process substitution to read env
  /\/proc\/self\/environ/,
  /\/proc\/\d+\/environ/,
];

// commands that should always be allowed even if they match a pattern
const ALLOWLIST = [
  /\bvault\s+run\b/,           // vault run -- <cmd> is the intended way
  /\bvault\s+login\b/,
  /\bvault\s+pull\b/,
  /\bvault\s+list\b/,
  /\bvault\s+init\b/,
  /\.env\.example/,            // .env.example is fine (no secrets)
  /\.env\.template/,
  /echo\s+["'][^$]*["']/,     // echo with literal strings (no $ expansion)
];

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
  });
}

async function main() {
  const raw = await readStdin();
  let input;
  try {
    input = JSON.parse(raw || '{}');
  } catch {
    process.stdout.write(raw);
    process.exit(0);
    return;
  }

  const cmd = String(input.input?.command || '');
  if (!cmd) {
    process.stdout.write(raw);
    process.exit(0);
    return;
  }

  // check allowlist first
  for (const pattern of ALLOWLIST) {
    if (pattern.test(cmd)) {
      process.stdout.write(raw);
      process.exit(0);
      return;
    }
  }

  // check blocked patterns
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(cmd)) {
      const reason = `[midsummer-vault] BLOCKED: "${cmd.substring(0, 80)}" — this command may expose secrets. Use \`vault run -- <command>\` to inject secrets safely into your process environment.`;
      process.stderr.write(reason + '\n');
      process.exit(2);
      return;
    }
  }

  process.stdout.write(raw);
  process.exit(0);
}

main().catch(() => process.exit(0));
