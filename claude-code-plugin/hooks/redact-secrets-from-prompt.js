#!/usr/bin/env node

/**
 * UserPromptSubmit hook: multi-layer secret detection and redaction.
 *
 * Scans user messages BEFORE the model sees them. Detected secrets are
 * auto-stored in the local vault and replaced with [vault:NAME] references.
 *
 * Detection pipeline (inspired by TruffleHog, Gitleaks, detect-secrets):
 *   Layer 1: Known prefixes (high confidence, ~200 services)
 *   Layer 2: Structural patterns (JWTs, connection strings, private keys)
 *   Layer 3: Entropy scoring (separate thresholds for hex vs base64 charsets)
 *   Layer 4: Keyword proximity (password/secret/key near a high-entropy value)
 *
 * Each detection includes a classification (api_key, access_token, etc.)
 * and confidence level (high, medium, low).
 */

const { execFileSync } = require('child_process');
const crypto = require('crypto');

// ─── Layer 1: Known Service Prefixes ────────────────────────────────────────
// high confidence, near-zero false positives
const KNOWN_PREFIXES = [
  // payment
  {
    pattern: /\bsk_live_[a-zA-Z0-9]{10,99}\b/g,
    name: 'STRIPE_SECRET',
    type: 'api_key',
    confidence: 'high',
  },
  {
    pattern: /\bsk_test_[a-zA-Z0-9]{10,99}\b/g,
    name: 'STRIPE_TEST',
    type: 'api_key',
    confidence: 'high',
  },
  {
    pattern: /\bpk_live_[a-zA-Z0-9]{10,99}\b/g,
    name: 'STRIPE_PUB',
    type: 'api_key',
    confidence: 'high',
  },
  {
    pattern: /\brk_live_[a-zA-Z0-9]{10,99}\b/g,
    name: 'STRIPE_RESTRICTED',
    type: 'api_key',
    confidence: 'high',
  },
  {
    pattern: /\bwhsec_[a-zA-Z0-9]{10,99}\b/g,
    name: 'STRIPE_WEBHOOK',
    type: 'webhook',
    confidence: 'high',
  },

  // AI providers
  {
    pattern: /\bsk-ant-api03-[a-zA-Z0-9_-]{80,}\b/g,
    name: 'ANTHROPIC_KEY',
    type: 'api_key',
    confidence: 'high',
  },
  {
    pattern: /\bsk-proj-[a-zA-Z0-9_-]{40,}\b/g,
    name: 'OPENAI_KEY',
    type: 'api_key',
    confidence: 'high',
  },
  {
    pattern: /\bsk-[a-zA-Z0-9]{40,50}\b/g,
    name: 'OPENAI_LEGACY',
    type: 'api_key',
    confidence: 'medium',
  },

  // cloud providers
  {
    pattern: /\bAKIA[A-Z2-7]{16}\b/g,
    name: 'AWS_ACCESS_KEY',
    type: 'access_key',
    confidence: 'high',
  },
  {
    pattern: /\bASIA[A-Z2-7]{16}\b/g,
    name: 'AWS_TEMP_KEY',
    type: 'access_key',
    confidence: 'high',
  },
  {
    pattern: /\bAIza[a-zA-Z0-9_-]{35}\b/g,
    name: 'GOOGLE_API_KEY',
    type: 'api_key',
    confidence: 'high',
  },
  {
    pattern: /\b[0-9]+-[a-z0-9]{32}\.apps\.googleusercontent\.com\b/g,
    name: 'GOOGLE_OAUTH',
    type: 'oauth_id',
    confidence: 'high',
  },
  {
    pattern: /\bAZ[A-Za-z0-9+/]{50,}\b/g,
    name: 'AZURE_KEY',
    type: 'api_key',
    confidence: 'medium',
  },

  // git platforms
  {
    pattern: /\bghp_[a-zA-Z0-9]{36,}\b/g,
    name: 'GITHUB_PAT',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bgho_[a-zA-Z0-9]{36,}\b/g,
    name: 'GITHUB_OAUTH',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bghu_[a-zA-Z0-9]{36,}\b/g,
    name: 'GITHUB_USER',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bghs_[a-zA-Z0-9]{36,}\b/g,
    name: 'GITHUB_APP',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bghr_[a-zA-Z0-9]{36,}\b/g,
    name: 'GITHUB_REFRESH',
    type: 'refresh_token',
    confidence: 'high',
  },
  {
    pattern: /\bgithub_pat_[a-zA-Z0-9_]{80,}\b/g,
    name: 'GITHUB_FINE_PAT',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bglpat-[a-zA-Z0-9_-]{20,}\b/g,
    name: 'GITLAB_PAT',
    type: 'access_token',
    confidence: 'high',
  },

  // messaging
  {
    pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g,
    name: 'SLACK_BOT',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b/g,
    name: 'SLACK_USER',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bxoxo-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b/g,
    name: 'SLACK_LEGACY',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bxapp-[0-9]{1}-[A-Za-z0-9]{30,}\b/g,
    name: 'SLACK_APP',
    type: 'access_token',
    confidence: 'high',
  },

  // email / comms
  {
    pattern: /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g,
    name: 'SENDGRID_KEY',
    type: 'api_key',
    confidence: 'high',
  },
  { pattern: /\bkey-[a-f0-9]{32}\b/g, name: 'MAILGUN_KEY', type: 'api_key', confidence: 'medium' },
  {
    pattern: /\bre_[a-zA-Z0-9]{30,}\b/g,
    name: 'RESEND_KEY',
    type: 'api_key',
    confidence: 'medium',
  },

  // databases / services
  {
    pattern: /\bnpm_[a-zA-Z0-9]{36,}\b/g,
    name: 'NPM_TOKEN',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bpypi-[a-zA-Z0-9_-]{50,}\b/g,
    name: 'PYPI_TOKEN',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bsntrys_[a-zA-Z0-9+/]{50,}\b/g,
    name: 'SENTRY_TOKEN',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bhvs\.[a-zA-Z0-9_-]{24,}\b/g,
    name: 'HASHICORP_TOKEN',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bhvb\.[a-zA-Z0-9_-]{100,}\b/g,
    name: 'HASHICORP_BATCH',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bLTAI[a-zA-Z0-9]{17,21}\b/g,
    name: 'ALIBABA_KEY',
    type: 'access_key',
    confidence: 'high',
  },
  {
    pattern: /\bvercel_[a-zA-Z0-9]{24,}\b/g,
    name: 'VERCEL_TOKEN',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bdop_v1_[a-f0-9]{64}\b/g,
    name: 'DOPPLER_TOKEN',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bSQOAIp-[a-zA-Z0-9_-]{22}\b/g,
    name: 'SQUARE_TOKEN',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bshpat_[a-fA-F0-9]{32}\b/g,
    name: 'SHOPIFY_PAT',
    type: 'access_token',
    confidence: 'high',
  },
  {
    pattern: /\bshpca_[a-fA-F0-9]{32}\b/g,
    name: 'SHOPIFY_CUSTOM',
    type: 'access_token',
    confidence: 'high',
  },
];

// ─── Layer 2: Structural Patterns ───────────────────────────────────────────
const STRUCTURAL_PATTERNS = [
  // JWTs: base64(header).base64(payload).signature — the `ey` prefix is base64 for `{"
  {
    pattern: /\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.[a-zA-Z0-9/\\_-]{10,}=*)\b/g,
    name: 'JWT',
    type: 'access_token',
    confidence: 'high',
  },

  // private keys (PEM)
  {
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{20,}?-----END/g,
    name: 'PRIVATE_KEY',
    type: 'private_key',
    confidence: 'high',
  },

  // connection strings with embedded credentials
  {
    pattern: /\b((?:postgres|mysql|mongodb|redis|amqp|mssql)(?:ql)?:\/\/[^\s'"]{10,})\b/g,
    name: 'CONNECTION_STRING',
    type: 'connection_string',
    confidence: 'high',
  },

  // AWS secret keys (40-char base64 near an AKIA)
  {
    pattern: /(?:aws.{0,20}secret|secret.{0,20}key)[=:\s]["']?([a-zA-Z0-9/+=]{40})["']?/gi,
    name: 'AWS_SECRET_KEY',
    type: 'secret_key',
    confidence: 'high',
    group: 1,
  },
];

// ─── Layer 3: Entropy-Based Detection ───────────────────────────────────────

// character set classifiers
const BASE64_CHARS = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');
const HEX_CHARS = new Set('0123456789abcdefABCDEF');

function charsetType(str) {
  let b64 = 0,
    hex = 0;
  for (const ch of str) {
    if (BASE64_CHARS.has(ch)) b64++;
    if (HEX_CHARS.has(ch)) hex++;
  }
  const len = str.length;
  if (hex / len > 0.95) return 'hex';
  if (b64 / len > 0.95) return 'base64';
  return 'mixed';
}

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// thresholds from detect-secrets (Yelp), tuned by charset
const ENTROPY_THRESHOLDS = {
  hex: 3.0, // max hex entropy ~4.0, threshold 3.0
  base64: 4.5, // max base64 entropy ~6.0, threshold 4.5
  mixed: 4.0, // general threshold
};

// match any contiguous 30+ alphanum/base64 token
const ENTROPY_CANDIDATE_RE = /(?<![a-zA-Z0-9_/+=\-])([a-zA-Z0-9_/+=\-]{30,})(?![a-zA-Z0-9_/+=\-])/g;

function looksLikeSecret(str) {
  if (str.length < 30) return false;

  // skip all-lowercase (English words, paths)
  if (/^[a-z]+$/.test(str)) return false;
  // skip all-uppercase (constants, acronyms)
  if (/^[A-Z_]+$/.test(str)) return false;
  // skip paths (multiple slashes)
  if (str.includes('/') && str.split('/').length > 2) return false;
  // skip URLs
  if (/^https?:/.test(str)) return false;
  // skip template variables
  if (/\$\{\{/.test(str) || /\{\{/.test(str)) return false;
  // skip repeated characters (aaaaaaa, 0000000)
  if (/^(.)\1+$/.test(str)) return false;
  // skip common placeholder patterns
  if (/^(your|changeme|placeholder|example|xxxxxxx|test)/i.test(str)) return false;

  const charset = charsetType(str);
  const entropy = shannonEntropy(str);
  const threshold = ENTROPY_THRESHOLDS[charset] || ENTROPY_THRESHOLDS.mixed;

  if (entropy < threshold) return false;

  // for hex strings, penalize all-digit sequences (phone numbers, timestamps)
  if (charset === 'hex' && /^\d+$/.test(str)) {
    return false;
  }

  // require mixed character types (upper+lower, or letter+digit)
  const hasUpper = /[A-Z]/.test(str);
  const hasLower = /[a-z]/.test(str);
  const hasDigit = /[0-9]/.test(str);
  const types = [hasUpper, hasLower, hasDigit].filter(Boolean).length;
  return types >= 2;
}

// ─── Layer 4: Keyword Proximity ─────────────────────────────────────────────
// if a high-entropy string appears near a secret-like keyword, boost confidence
const SECRET_KEYWORDS =
  /\b(password|passwd|pwd|secret|token|key|apikey|api_key|credential|auth|private|access_key|secret_key|bearer|authorization)\b/gi;

function hasKeywordNearby(prompt, secretStart, secretEnd) {
  // check 80 chars before and after the secret
  const windowStart = Math.max(0, secretStart - 80);
  const windowEnd = Math.min(prompt.length, secretEnd + 80);
  const window = prompt.substring(windowStart, windowEnd);
  return SECRET_KEYWORDS.test(window);
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
  });
}

function shortHash(value) {
  return crypto.createHash('sha256').update(value).digest('hex').substring(0, 8);
}

function tryStoreInVault(name, value) {
  try {
    execFileSync('vault', ['set', name, value], { stdio: 'pipe', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

// suggest a standard env var name based on classification
function suggestEnvName(name, type) {
  const map = {
    STRIPE_SECRET: 'STRIPE_SECRET_KEY',
    STRIPE_TEST: 'STRIPE_TEST_KEY',
    STRIPE_PUB: 'STRIPE_PUBLISHABLE_KEY',
    STRIPE_RESTRICTED: 'STRIPE_RESTRICTED_KEY',
    STRIPE_WEBHOOK: 'STRIPE_WEBHOOK_SECRET',
    ANTHROPIC_KEY: 'ANTHROPIC_API_KEY',
    OPENAI_KEY: 'OPENAI_API_KEY',
    OPENAI_LEGACY: 'OPENAI_API_KEY',
    AWS_ACCESS_KEY: 'AWS_ACCESS_KEY_ID',
    AWS_TEMP_KEY: 'AWS_ACCESS_KEY_ID',
    AWS_SECRET_KEY: 'AWS_SECRET_ACCESS_KEY',
    GOOGLE_API_KEY: 'GOOGLE_API_KEY',
    GOOGLE_OAUTH: 'GOOGLE_CLIENT_ID',
    GITHUB_PAT: 'GITHUB_TOKEN',
    GITHUB_FINE_PAT: 'GITHUB_TOKEN',
    GITLAB_PAT: 'GITLAB_TOKEN',
    SLACK_BOT: 'SLACK_BOT_TOKEN',
    SLACK_USER: 'SLACK_USER_TOKEN',
    SENDGRID_KEY: 'SENDGRID_API_KEY',
    MAILGUN_KEY: 'MAILGUN_API_KEY',
    RESEND_KEY: 'RESEND_API_KEY',
    NPM_TOKEN: 'NPM_TOKEN',
    SENTRY_TOKEN: 'SENTRY_AUTH_TOKEN',
    VERCEL_TOKEN: 'VERCEL_TOKEN',
    JWT: 'AUTH_TOKEN',
    CONNECTION_STRING: 'DATABASE_URL',
    PRIVATE_KEY: 'PRIVATE_KEY',
  };
  // strip the hash suffix to look up base name
  const baseName = name.replace(/_[a-f0-9]{8}$/, '');
  return map[baseName] || baseName;
}

function replaceAndTrack(modified, secretValue, name, type, confidence, stored) {
  const hash = shortHash(secretValue);
  const vaultName = `${name}_${hash}`;
  const didStore = tryStoreInVault(vaultName, secretValue);
  const replacement = didStore ? `[vault:${vaultName}]` : `[REDACTED:${name}]`;
  return {
    text: modified.replace(secretValue, replacement),
    entry: { name: vaultName, type, confidence, stored: didStore },
  };
}

// ─── Main ───────────────────────────────────────────────────────────────────

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

  const prompt = input.input?.prompt || input.prompt || '';
  if (!prompt || typeof prompt !== 'string') {
    process.stdout.write(raw);
    process.exit(0);
    return;
  }

  let modified = prompt;
  const stored = [];

  // layer 1: known service prefixes
  for (const { pattern, name, type, confidence } of KNOWN_PREFIXES) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(modified)) !== null) {
      const val = match[0];
      if (val.length < 10) continue;
      const result = replaceAndTrack(modified, val, name, type, confidence, stored);
      modified = result.text;
      stored.push(result.entry);
      pattern.lastIndex = 0;
    }
  }

  // layer 2: structural patterns
  for (const { pattern, name, type, confidence, group } of STRUCTURAL_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(modified)) !== null) {
      const val = group !== undefined ? match[group] : match[0];
      if (!val || val.length < 10) continue;
      if (val.includes('[vault:')) continue;
      const result = replaceAndTrack(modified, val, name, type, confidence, stored);
      modified = result.text;
      stored.push(result.entry);
      pattern.lastIndex = 0;
    }
  }

  // layer 3: entropy-based detection
  ENTROPY_CANDIDATE_RE.lastIndex = 0;
  let eMatch;
  while ((eMatch = ENTROPY_CANDIDATE_RE.exec(modified)) !== null) {
    const candidate = eMatch[1];
    if (candidate.includes('[vault:') || candidate.includes('[REDACTED:')) continue;
    if (!looksLikeSecret(candidate)) continue;

    // layer 4: keyword proximity boosts confidence
    const nearKeyword = hasKeywordNearby(modified, eMatch.index, eMatch.index + candidate.length);
    const confidence = nearKeyword ? 'high' : 'medium';
    const type = nearKeyword ? 'credential' : 'unknown_secret';

    const result = replaceAndTrack(modified, candidate, 'SECRET', type, confidence, stored);
    modified = result.text;
    stored.push(result.entry);
    ENTROPY_CANDIDATE_RE.lastIndex = 0;
  }

  // output
  if (stored.length > 0) {
    // stderr: inform the user
    const lines = ['[midsummer-vault] Detected secrets in your message:'];
    for (const s of stored) {
      const icon = s.stored ? 'stored' : 'redacted';
      lines.push(`  ${icon}: ${s.name} (${s.type}, ${s.confidence} confidence)`);
    }
    lines.push('  Values replaced with [vault:NAME] references.');
    process.stderr.write(lines.join('\n') + '\n');

    // inject context into the prompt so the model knows what to do
    // this is the key: the model sees instructions, not secret values
    const needsNaming = stored.filter((s) => s.name.startsWith('SECRET_'));
    const autoNamed = stored.filter((s) => !s.name.startsWith('SECRET_'));

    let guidance = '\n\n<vault-context>\n';
    guidance += 'Secrets were detected in this message and stored in the local vault.\n';
    guidance += 'You can see [vault:NAME] references but NEVER the actual values.\n\n';

    if (autoNamed.length > 0) {
      guidance += 'Auto-classified secrets:\n';
      for (const s of autoNamed) {
        const suggestedEnv = suggestEnvName(s.name, s.type);
        guidance += `  - ${s.name} (${s.type}) → suggested env var: ${suggestedEnv}\n`;
      }
    }

    if (needsNaming.length > 0) {
      guidance += 'Unclassified secrets (need env var names):\n';
      for (const s of needsNaming) {
        guidance += `  - ${s.name} (${s.type})\n`;
      }
      guidance += '\nIMPORTANT: Ask the user what environment variable name to use for each\n';
      guidance += 'unclassified secret. Then run: vault rename SECRET_xxx ENV_VAR_NAME\n';
      guidance += 'This maps the secret to the correct env var for vault run.\n';
    }

    if (autoNamed.length > 0) {
      guidance += '\nFor auto-classified secrets, confirm the env var name with the user,\n';
      guidance += 'then run: vault rename CURRENT_NAME DESIRED_NAME\n';
    }

    guidance += '\nTo use secrets in commands: vault run -- <command>\n';
    guidance += 'To list stored secrets: vault list\n';
    guidance += '</vault-context>';

    modified += guidance;
  }

  if (modified !== prompt) {
    if (input.input?.prompt !== undefined) {
      input.input.prompt = modified;
    } else if (input.prompt !== undefined) {
      input.prompt = modified;
    }
    process.stdout.write(JSON.stringify(input));
  } else {
    process.stdout.write(raw);
  }

  process.exit(0);
}

main().catch(() => process.exit(0));
