#!/usr/bin/env node

// PreToolUse hook for Write: blocks writing secrets directly into files.
// Prevents agents from writing .env files with actual secret values.
// Exit code 2 = block. Exit code 0 = allow.

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

  const filePath = String(input.input?.file_path || '');
  const content = String(input.input?.content || '');

  // allow .env.example, .env.template (no real secrets)
  if (/\.env\.(example|template|sample)$/i.test(filePath)) {
    process.stdout.write(raw);
    process.exit(0);
    return;
  }

  // block writing to .env files if content contains what looks like real secrets
  if (/\.env(\.local|\.production|\.staging)?$/i.test(filePath)) {
    // check if content has values that look like actual secrets (not placeholders)
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('#') || !trimmed.includes('=')) continue;

      const eqIdx = trimmed.indexOf('=');
      const key = trimmed.substring(0, eqIdx).trim();
      const value = trimmed.substring(eqIdx + 1).trim().replace(/^["']|["']$/g, '');

      // skip placeholder values
      if (!value || value === 'your-key-here' || value === 'changeme' || value.startsWith('<') || value.startsWith('${')) continue;

      // flag keys that look like secrets with real-looking values
      if (/(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE)/i.test(key) && value.length > 8) {
        const reason = `[midsummer-vault] BLOCKED: Writing secrets to ${filePath} — store secrets in the vault instead.\n` +
          `  Run: vault run -- <command>  (secrets are injected as env vars)\n` +
          `  Or use .env.example with placeholder values.`;
        process.stderr.write(reason + '\n');
        process.exit(2);
        return;
      }
    }
  }

  process.stdout.write(raw);
  process.exit(0);
}

main().catch(() => process.exit(0));
