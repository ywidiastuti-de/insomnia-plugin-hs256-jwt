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

function readFaultSecret(project, filepath, property) {
  const homeDir = os.homedir();
  const isWindows = os.platform() === 'win32';

  // Windows: colons are invalid in paths — strip them (matches insomnia-plugin-fault-variables)
  const resolvedProject = isWindows ? project.replace(/:/g, '') : project;

  const credPath = path.join(homeDir, '.fault', resolvedProject, filepath);
  if (!fs.existsSync(credPath)) {
    throw new Error(`Fault credentials not found: ${credPath}`);
  }

  const props = propertiesReader({ sourceFile: credPath });
  const value = props.get(property);
  if (value === null || value === undefined) {
    throw new Error(`Property "${property}" not found in ${credPath}`);
  }
  return String(value);
}

module.exports.templateTags = [
  {
    name: 'hs256jwt',
    displayName: 'HS256 JWT',
    description: 'Generate an HS256 JWT — reads signing secret directly from fault credentials',
    args: [
      {
        displayName: 'Fault Project',
        description: 'Fault project ID, e.g. com.example.app:api',
        type: 'string',
        defaultValue: '',
      },
      {
        displayName: 'Fault Filepath',
        description: 'Path within the fault project, e.g. local/.properties',
        type: 'string',
        defaultValue: 'local/.properties',
      },
      {
        displayName: 'Secret Property',
        description: 'Property key for the JWT signing secret',
        type: 'string',
        defaultValue: 'jwt.secret',
      },
      {
        displayName: 'Tenant ID',
        description: 'Value of the tenant_id claim; leave empty to omit the claim',
        type: 'string',
        defaultValue: '',
      },
      {
        displayName: 'Expiry (seconds)',
        type: 'number',
        defaultValue: 3600,
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
    ],
    async run(context, project, filepath, secretProperty, tenantId, expiresIn, secretEncoding) {
      project = resolveRef(context, project);
      filepath = resolveRef(context, filepath);
      secretProperty = resolveRef(context, secretProperty);
      tenantId = resolveRef(context, tenantId);

      if (!project) throw new Error('Fault project is required');
      if (!filepath) throw new Error('Fault filepath is required');
      if (!secretProperty) throw new Error('Secret property is required');

      const secretStr = readFaultSecret(project, filepath, secretProperty);
      const secretKey = (secretEncoding === 'base64')
        ? Buffer.from(secretStr, 'base64')
        : secretStr;

      const header = { alg: 'HS256', typ: 'JWT' };
      const now = Math.floor(Date.now() / 1000);
      // Backdate iat to absorb clock skew — servers reject tokens whose iat
      // they consider to be in the future, which happens when the token is sent
      // in the same instant it is generated.
      const payload = {
        ...(tenantId ? { tenant_id: tenantId } : {}),
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
