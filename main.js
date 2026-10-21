const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { propertiesReader } = require('properties-reader');

// Seconds to backdate `iat` by, so a token sent immediately after generation is
// not rejected as future-dated by a server whose clock runs slightly behind.
const CLOCK_SKEW_LEEWAY = 60;

function isUnresolvedRef(v) {
  return typeof v === 'string' && /^_[.\[]/.test(v);
}

function resolveRef(context, value) {
  if (!isUnresolvedRef(value)) return value;
  const m = value.match(/^_\.(.+)$/) || value.match(/^_\[['"](.+)['"]\]$/);
  const varName = m && m[1];
  if (!varName) return value;

  const envs = [
    context && context.context,
    context && context.request && context.request.environment,
    context && context.environment,
  ];
  for (const env of envs) {
    if (env && env[varName] != null) return String(env[varName]);
  }
  throw new Error(`Could not resolve environment variable "${varName}" — use {{ _.${varName} }} syntax instead`);
}

function base64url(buffer) {
  return buffer.toString('base64')
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function expandHome(filepath) {
  if (filepath === '~') return os.homedir();
  if (filepath.startsWith('~/') || filepath.startsWith('~\\')) {
    return path.join(os.homedir(), filepath.slice(2));
  }
  return filepath;
}

function readSecretFromFile(filepath, property) {
  const fullPath = expandHome(filepath);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Secret file not found: ${fullPath}`);
  }
  const props = propertiesReader({ sourceFile: fullPath });
  const value = props.get(property);
  if (value === null || value === undefined) {
    throw new Error(`Property "${property}" not found in ${fullPath}`);
  }
  return String(value);
}

function parseClaims(claimsJson) {
  if (!claimsJson || !claimsJson.trim()) return {};
  let claims;
  try {
    claims = JSON.parse(claimsJson);
  } catch (e) {
    throw new Error(`Extra claims must be valid JSON: ${e.message}`);
  }
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new Error('Extra claims must be a JSON object, e.g. {"sub": "user-1"}');
  }
  return claims;
}

const isFileSource = args => args[0] && args[0].value === 'file';

module.exports.templateTags = [
  {
    name: 'hs256jwt',
    displayName: 'HS256 JWT',
    description: 'Generate an HS256 JWT signed with a shared secret',
    args: [
      {
        displayName: 'Secret Source',
        type: 'enum',
        options: [
          { displayName: 'Value (type it or use an environment variable)', value: 'value' },
          { displayName: 'Properties file', value: 'file' },
        ],
        defaultValue: 'value',
      },
      {
        displayName: 'Secret',
        description: 'The signing secret, e.g. {{ _.jwtSecret }}',
        type: 'string',
        defaultValue: '',
        hide: isFileSource,
      },
      {
        displayName: 'Properties File',
        description: 'Path to a .properties file; ~ expands to your home directory',
        type: 'string',
        defaultValue: '~/secrets/app.properties',
        hide: args => !isFileSource(args),
      },
      {
        displayName: 'Secret Property',
        description: 'Key of the signing secret inside the properties file',
        type: 'string',
        defaultValue: 'jwt.secret',
        hide: args => !isFileSource(args),
      },
      {
        displayName: 'Secret Encoding',
        description: 'utf8 = use secret as-is; base64 = decode secret from Base64 before signing (common in Spring Boot)',
        type: 'enum',
        options: [
          { displayName: 'UTF-8 (raw string)', value: 'utf8' },
          { displayName: 'Base64 (decode first)', value: 'base64' },
        ],
        defaultValue: 'utf8',
      },
      {
        displayName: 'Expiry (seconds)',
        type: 'number',
        defaultValue: 3600,
      },
      {
        displayName: 'Extra Claims (JSON)',
        description: 'Claims added to the payload, e.g. {"sub": "user-1", "tenant_id": "acme"}',
        type: 'string',
        defaultValue: '{}',
      },
    ],
    async run(context, source, secret, filepath, secretProperty, secretEncoding, expiresIn, claimsJson) {
      let secretStr;
      if (source === 'file') {
        filepath = resolveRef(context, filepath);
        secretProperty = resolveRef(context, secretProperty);
        if (!filepath) throw new Error('Properties file is required');
        if (!secretProperty) throw new Error('Secret property is required');
        secretStr = readSecretFromFile(filepath, secretProperty);
      } else {
        secretStr = resolveRef(context, secret);
        if (!secretStr) throw new Error('Secret is required');
      }

      const secretKey = (secretEncoding === 'base64')
        ? Buffer.from(secretStr, 'base64')
        : secretStr;

      const header = { alg: 'HS256', typ: 'JWT' };
      const now = Math.floor(Date.now() / 1000);
      // Backdate iat to absorb clock skew — servers reject tokens whose iat
      // they consider to be in the future, which happens when the token is sent
      // in the same instant it is generated.
      const payload = {
        ...parseClaims(claimsJson),
        iat: now - CLOCK_SKEW_LEEWAY,
        exp: now + Number(expiresIn || 3600),
      };

      const encHeader = base64url(Buffer.from(JSON.stringify(header)));
      const encPayload = base64url(Buffer.from(JSON.stringify(payload)));
      const signingInput = `${encHeader}.${encPayload}`;
      const signature = base64url(crypto.createHmac('sha256', secretKey).update(signingInput).digest());

      return `${signingInput}.${signature}`;
    },
  },
];
