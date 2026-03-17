#!/usr/bin/env node

/**
 * UserPromptSubmit hook: multi-layer secret detection and redaction.
 * Scans user messages BEFORE the model sees them.
 *
 * IMPORTANT: This hook MUST NOT crash. Any error = passthrough.
 */

let crypto;
try { crypto = require('node:crypto'); } catch { crypto = require('crypto'); }

// ─── Layer 1: Known Service Prefixes ────────────────────────────────────────
const KNOWN = [
  [/\bsk_live_[a-zA-Z0-9]{10,99}\b/g, 'STRIPE_SECRET', 'api_key'],
  [/\bsk_test_[a-zA-Z0-9]{10,99}\b/g, 'STRIPE_TEST', 'api_key'],
  [/\bpk_live_[a-zA-Z0-9]{10,99}\b/g, 'STRIPE_PUB', 'api_key'],
  [/\bsk-ant-api03-[a-zA-Z0-9_-]{80,}\b/g, 'ANTHROPIC_KEY', 'api_key'],
  [/\bsk-proj-[a-zA-Z0-9_-]{40,}\b/g, 'OPENAI_KEY', 'api_key'],
  [/\bsk-[a-zA-Z0-9]{40,50}\b/g, 'OPENAI_LEGACY', 'api_key'],
  [/\bAKIA[A-Z2-7]{16}\b/g, 'AWS_ACCESS_KEY', 'access_key'],
  [/\bAIza[a-zA-Z0-9_-]{35}\b/g, 'GOOGLE_API_KEY', 'api_key'],
  [/\bghp_[a-zA-Z0-9]{36,}\b/g, 'GITHUB_PAT', 'access_token'],
  [/\bgho_[a-zA-Z0-9]{36,}\b/g, 'GITHUB_OAUTH', 'access_token'],
  [/\bgithub_pat_[a-zA-Z0-9_]{80,}\b/g, 'GITHUB_FINE_PAT', 'access_token'],
  [/\bglpat-[a-zA-Z0-9_-]{20,}\b/g, 'GITLAB_PAT', 'access_token'],
  [/\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g, 'SLACK_BOT', 'access_token'],
  [/\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b/g, 'SLACK_USER', 'access_token'],
  [/\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g, 'SENDGRID_KEY', 'api_key'],
  [/\bnpm_[a-zA-Z0-9]{36,}\b/g, 'NPM_TOKEN', 'access_token'],
  [/\bvercel_[a-zA-Z0-9]{24,}\b/g, 'VERCEL_TOKEN', 'access_token'],
  [/\bsntrys_[a-zA-Z0-9+/]{50,}\b/g, 'SENTRY_TOKEN', 'access_token'],
  [/\bhvs\.[a-zA-Z0-9_-]{24,}\b/g, 'HASHICORP_TOKEN', 'access_token'],
  [/\bshpat_[a-fA-F0-9]{32}\b/g, 'SHOPIFY_PAT', 'access_token'],
  [/\bre_[a-zA-Z0-9]{30,}\b/g, 'RESEND_KEY', 'api_key'],
];

// ─── Layer 2: Structural ────────────────────────────────────────────────────
const STRUCTURAL = [
  [/\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.[a-zA-Z0-9/\\_-]{10,}=*)\b/g, 'JWT', 'access_token'],
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{20,}?-----END/g, 'PRIVATE_KEY', 'private_key'],
  [/\b((?:postgres|mysql|mongodb|redis|amqp|mssql)(?:ql)?:\/\/[^\s'"]{10,})\b/g, 'CONNECTION_STRING', 'connection_string'],
];

// ─── Layer 3: Entropy ───────────────────────────────────────────────────────
const B64 = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');
const HEX = new Set('0123456789abcdefABCDEF');
const THRESHOLDS = { hex: 3.0, base64: 4.5, mixed: 4.0 };
const ENTROPY_RE = /(?<![a-zA-Z0-9_/+=\-])([a-zA-Z0-9_/+=\-]{30,})(?![a-zA-Z0-9_/+=\-])/g;
const KW_RE = /\b(password|passwd|pwd|secret|token|key|apikey|api_key|credential|auth|private|access_key|secret_key|bearer)\b/gi;

function entropy(s) {
  const f = {}; for (const c of s) f[c] = (f[c]||0)+1;
  let h = 0; const n = s.length;
  for (const v of Object.values(f)) { const p = v/n; h -= p * Math.log2(p); }
  return h;
}

function charset(s) {
  let b=0, h=0;
  for (const c of s) { if (B64.has(c)) b++; if (HEX.has(c)) h++; }
  if (h/s.length > 0.95) return 'hex';
  if (b/s.length > 0.95) return 'base64';
  return 'mixed';
}

function looksSecret(s) {
  if (s.length < 30) return false;
  if (/^[a-z]+$/.test(s) || /^[A-Z_]+$/.test(s)) return false;
  if (s.includes('/') && s.split('/').length > 2) return false;
  if (/^https?:/.test(s) || /\$\{\{/.test(s) || /^(.)\1+$/.test(s)) return false;
  if (/^(your|changeme|placeholder|example|xxxxxxx|test)/i.test(s)) return false;
  if (/^\d+$/.test(s)) return false;
  const e = entropy(s); const t = THRESHOLDS[charset(s)] || 4.0;
  if (e < t) return false;
  const u=/[A-Z]/.test(s), l=/[a-z]/.test(s), d=/[0-9]/.test(s);
  return [u,l,d].filter(Boolean).length >= 2;
}

const ENV_MAP = {
  STRIPE_SECRET:'STRIPE_SECRET_KEY', STRIPE_TEST:'STRIPE_TEST_KEY',
  ANTHROPIC_KEY:'ANTHROPIC_API_KEY', OPENAI_KEY:'OPENAI_API_KEY',
  AWS_ACCESS_KEY:'AWS_ACCESS_KEY_ID', GOOGLE_API_KEY:'GOOGLE_API_KEY',
  GITHUB_PAT:'GITHUB_TOKEN', GITLAB_PAT:'GITLAB_TOKEN',
  SLACK_BOT:'SLACK_BOT_TOKEN', SENDGRID_KEY:'SENDGRID_API_KEY',
  NPM_TOKEN:'NPM_TOKEN', VERCEL_TOKEN:'VERCEL_TOKEN',
  JWT:'AUTH_TOKEN', CONNECTION_STRING:'DATABASE_URL', PRIVATE_KEY:'PRIVATE_KEY',
};

function hash(v) { return crypto.createHash('sha256').update(v).digest('hex').slice(0,8); }
function envName(n) { return ENV_MAP[n.replace(/_[a-f0-9]{8}$/,'')] || n; }

function tryStore(name, value) {
  try {
    require('child_process').execFileSync('vault', ['set', name, value], {
      stdio: 'pipe', timeout: 5000, env: { ...process.env, PATH: process.env.PATH + ':/usr/local/bin:/opt/homebrew/bin' }
    });
    return true;
  } catch { return false; }
}

// ─── Main ───────────────────────────────────────────────────────────────────
function readStdin() {
  return new Promise(r => {
    let d = ''; process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => d += c);
    process.stdin.on('end', () => r(d));
    // timeout: if no data in 3s, resolve with empty
    setTimeout(() => r(d || ''), 3000);
  });
}

async function main() {
  let raw;
  try { raw = await readStdin(); } catch { process.exit(0); return; }
  if (!raw || !raw.trim()) { process.exit(0); return; }

  let input;
  try { input = JSON.parse(raw); } catch { process.stdout.write(raw); process.exit(0); return; }

  // extract prompt from various possible input shapes
  const prompt = String(
    input?.input?.prompt || input?.prompt || input?.message || input?.content || ''
  );

  if (!prompt) { process.stdout.write(raw); process.exit(0); return; }

  let text = prompt;
  const found = [];

  // layer 1: known prefixes
  for (const [re, name, type] of KNOWN) {
    const pat = new RegExp(re.source, re.flags);
    let m;
    while ((m = pat.exec(text)) !== null) {
      if (m[0].length < 10) continue;
      const h = hash(m[0]); const ref = `${name}_${h}`;
      const ok = tryStore(ref, m[0]);
      text = text.replace(m[0], ok ? `[vault:${ref}]` : `[REDACTED:${name}]`);
      found.push({ ref, type, auto: true, env: envName(name) });
      pat.lastIndex = 0;
    }
  }

  // layer 2: structural
  for (const [re, name, type] of STRUCTURAL) {
    const pat = new RegExp(re.source, re.flags);
    let m;
    while ((m = pat.exec(text)) !== null) {
      const v = m[1] || m[0];
      if (v.length < 10 || v.includes('[vault:')) continue;
      const h = hash(v); const ref = `${name}_${h}`;
      const ok = tryStore(ref, v);
      text = text.replace(v, ok ? `[vault:${ref}]` : `[REDACTED:${name}]`);
      found.push({ ref, type, auto: true, env: envName(name) });
      pat.lastIndex = 0;
    }
  }

  // layer 3+4: entropy + keyword proximity
  ENTROPY_RE.lastIndex = 0;
  let em;
  while ((em = ENTROPY_RE.exec(text)) !== null) {
    const c = em[1];
    if (c.includes('[vault:') || c.includes('[REDACTED:')) continue;
    if (!looksSecret(c)) continue;
    const h = hash(c); const ref = `SECRET_${h}`;
    const ok = tryStore(ref, c);
    text = text.replace(c, ok ? `[vault:${ref}]` : `[REDACTED:SECRET]`);
    const win = text.substring(Math.max(0,em.index-80), Math.min(text.length,em.index+c.length+80));
    KW_RE.lastIndex = 0;
    const nearKw = KW_RE.test(win);
    found.push({ ref, type: nearKw ? 'credential' : 'unknown', auto: false });
    ENTROPY_RE.lastIndex = 0;
  }

  if (found.length > 0) {
    // stderr: user notification
    const parts = ['[midsummer-vault] Detected secrets:'];
    for (const f of found) parts.push(`  ${f.ref} (${f.type})`);
    process.stderr.write(parts.join('\n') + '\n');

    // append guidance to prompt
    let g = '\n\n<vault-context>\nSecrets detected and stored in local vault.\n';
    const auto = found.filter(f => f.auto);
    const manual = found.filter(f => !f.auto);
    if (auto.length) {
      g += 'Auto-classified:\n';
      for (const f of auto) g += `  [vault:${f.ref}] (${f.type}) -> env: ${f.env}\n`;
    }
    if (manual.length) {
      g += 'Needs naming (ask user what env var):\n';
      for (const f of manual) g += `  [vault:${f.ref}] (${f.type})\n`;
      g += 'Run: vault rename SECRET_xxx ENV_VAR_NAME\n';
    }
    g += 'Run commands with secrets: vault run -- <cmd>\n';
    g += 'If vault not initialized: vault init\n';
    g += '</vault-context>';
    text += g;
  }

  // write back modified input
  if (text !== prompt) {
    if (input?.input?.prompt !== undefined) input.input.prompt = text;
    else if (input?.prompt !== undefined) input.prompt = text;
    else if (input?.message !== undefined) input.message = text;
    else if (input?.content !== undefined) input.content = text;
    process.stdout.write(JSON.stringify(input));
  } else {
    process.stdout.write(raw);
  }
  process.exit(0);
}

main().catch(() => { try { process.stdout.write(''); } catch {} process.exit(0); });
