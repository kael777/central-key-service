// 最小 OIDC Provider，仅用于本地联调/测试：discovery、JWKS、authorize、token。
// 用法：node tools/mock-idp.mjs [port]
import http from 'node:http';
import crypto from 'node:crypto';

const port = Number(process.argv[2] || 9999);
const issuer = `http://127.0.0.1:${port}`;
const clientId = process.env.MOCK_CLIENT_ID || 'cms-key';
const kid = 'k1';

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = publicKey.export({ format: 'jwk' });

const codes = new Map(); // code -> { nonce, username, groups }

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signIdToken({ nonce, username, groups }) {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    aud: clientId,
    sub: `user-${username}`,
    preferred_username: username,
    groups,
    nonce,
    iat: now,
    exp: now + 300,
  };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = crypto.sign('sha256', Buffer.from(input), privateKey);
  return `${input}.${b64url(sig)}`;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, issuer);

  if (url.pathname === '/.well-known/openid-configuration') {
    return send(res, 200, {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
    });
  }

  if (url.pathname === '/jwks') {
    return send(res, 200, {
      keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }],
    });
  }

  if (url.pathname === '/authorize') {
    const redirectUri = url.searchParams.get('redirect_uri');
    const state = url.searchParams.get('state') || '';
    const nonce = url.searchParams.get('nonce') || '';
    if (url.searchParams.get('client_id') !== clientId || !redirectUri) {
      return send(res, 400, { error: 'invalid_request' });
    }
    const code = crypto.randomBytes(16).toString('hex');
    codes.set(code, {
      nonce,
      username: process.env.MOCK_USER || 'alice',
      groups: (process.env.MOCK_GROUPS || 'cms-admins').split(','),
    });
    const target = new URL(redirectUri);
    target.searchParams.set('code', code);
    target.searchParams.set('state', state);
    res.writeHead(302, { Location: target.toString() });
    return res.end();
  }

  if (url.pathname === '/token' && req.method === 'POST') {
    let body = '';
    for await (const chunk of req) body += chunk;
    const form = new URLSearchParams(body);
    const code = form.get('code');
    const entry = codes.get(code);
    if (!entry) {
      return send(res, 400, { error: 'invalid_grant' });
    }
    codes.delete(code);
    const idToken = signIdToken(entry);
    return send(res, 200, {
      access_token: 'mock-access-token',
      token_type: 'Bearer',
      expires_in: 300,
      id_token: idToken,
    });
  }

  send(res, 404, { error: 'not_found', path: url.pathname });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`mock idp: ${issuer} (client_id=${clientId})`);
});
