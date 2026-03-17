#!/usr/bin/env node

// UserPromptSubmit hook: warns if the user's prompt contains what looks like a secret.
// Does NOT block — just warns. Users may legitimately paste secrets to store them.

const SECRET_PATTERNS = [
  /sk_live_[a-zA-Z0-9]{20,}/,          // Stripe live key
  /sk_test_[a-zA-Z0-9]{20,}/,          // Stripe test key
  /ghp_[a-zA-Z0-9]{36,}/,              // GitHub PAT
  /gho_[a-zA-Z0-9]{36,}/,              // GitHub OAuth
  /github_pat_[a-zA-Z0-9_]{80,}/,      // GitHub fine-grained PAT
  /xoxb-[a-zA-Z0-9\-]{50,}/,           // Slack bot token
  /xoxp-[a-zA-Z0-9\-]{50,}/,           // Slack user token
  /AKIA[0-9A-Z]{16}/,                   // AWS access key
  /eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/, // JWT
  /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, // Private key
  /AIza[a-zA-Z0-9_-]{35}/,             // Google API key
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

  const prompt = String(input.input?.prompt || input.prompt || '');
  if (!prompt) {
    process.stdout.write(raw);
    process.exit(0);
    return;
  }

  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(prompt)) {
      process.stderr.write(
        '[midsummer-vault] WARNING: Your message may contain a secret or API key. ' +
        'Consider storing it in the vault instead of pasting it in chat.\n' +
        '  Run: curl -X POST http://your-vault/api/vault/{projectId}/secrets \\\n' +
        '    -H "Authorization: Bearer $TOKEN" \\\n' +
        '    -d \'{"name": "KEY_NAME", "value": "..."}\'\n'
      );
      break; // warn once, don't spam
    }
  }

  // never block — just warn
  process.stdout.write(raw);
  process.exit(0);
}

main().catch(() => process.exit(0));
