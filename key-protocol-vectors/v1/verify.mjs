// 獨立驗證器：讀取 vectors.json，模擬各語言 SDK 的 CI 檢查
// 用法：node verify.mjs [vectors.json]
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const file = process.argv[2] || path.join(here, 'vectors.json');
const doc = JSON.parse(fs.readFileSync(file, 'utf8'));

const PREFIX = 'KEY1.';
const SPKI_LEN = 91;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

const info = (kid, purpose) => Buffer.from(`cms-key-v1|${kid}|${purpose}`, 'utf8');
const aad = (kid, purpose) => Buffer.concat([Buffer.from(kid, 'utf8'), Buffer.from([0]), Buffer.from(purpose, 'utf8')]);
const b64u = (b) => Buffer.from(b).toString('base64url');

function keysFrom(jwkLike) {
  const pub = crypto.createPublicKey({ key: jwkLike, format: 'jwk' });
  return { pub, der: pub.export({ type: 'spki', format: 'der' }) };
}

function keypair(dHex) {
  const e = crypto.createECDH('prime256v1');
  e.setPrivateKey(Buffer.from(dHex, 'hex'));
  const raw = e.getPublicKey();
  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: raw.subarray(1, 33).toString('base64url'),
    y: raw.subarray(33, 65).toString('base64url'),
  };
  return {
    d: Buffer.from(dHex, 'hex'),
    jwk,
    priv: crypto.createPrivateKey({ key: { ...jwk, d: b64u(Buffer.from(dHex, 'hex')) }, format: 'jwk' }),
    ...keysFrom(jwk),
  };
}

class KeyError extends Error { constructor(code) { super(code); this.code = code; } }

function parse(token) {
  if (typeof token !== 'string' || !token.startsWith(PREFIX)) throw new KeyError('ERR_FORMAT');
  const rest = token.slice(PREFIX.length);
  const i = rest.indexOf('.');
  if (i <= 0) throw new KeyError('ERR_FORMAT');
  const kid = rest.slice(0, i);
  const body = rest.slice(i + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(body)) throw new KeyError('ERR_FORMAT');
  const p = Buffer.from(body, 'base64url');
  if (p.length < 1 + SPKI_LEN + IV_LEN + TAG_LEN) throw new KeyError('ERR_FORMAT');
  if (p[0] !== 1) throw new KeyError('ERR_FORMAT');
  return {
    kid,
    spki: p.subarray(1, 1 + SPKI_LEN),
    iv: p.subarray(1 + SPKI_LEN, 1 + SPKI_LEN + IV_LEN),
    ct: p.subarray(1 + SPKI_LEN + IV_LEN, p.length - TAG_LEN),
    tag: p.subarray(p.length - TAG_LEN),
  };
}

function decrypt(token, kid, purpose, priv) {
  const t = parse(token);
  if (t.kid !== kid) throw new KeyError('ERR_UNKNOWN_KID');
  let eph;
  try { eph = crypto.createPublicKey({ key: t.spki, format: 'der', type: 'spki' }); }
  catch { throw new KeyError('ERR_KEY'); }
  let shared;
  try { shared = crypto.diffieHellman({ privateKey: priv, publicKey: eph }); }
  catch { throw new KeyError('ERR_KEY'); }
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), info(kid, purpose), KEY_LEN));
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, t.iv);
    d.setAAD(aad(kid, purpose));
    d.setAuthTag(t.tag);
    return Buffer.concat([d.update(t.ct), d.final()]);
  } catch { throw new KeyError('ERR_AUTH'); }
}

function encryptWith(recipientDer, kid, purpose, plaintext, ephD, iv) {
  const eph = keypair(ephD);
  const recipient = crypto.createPublicKey({ key: recipientDer, format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({ privateKey: eph.priv, publicKey: recipient });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), info(kid, purpose), KEY_LEN));
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad(kid, purpose));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const payload = Buffer.concat([Buffer.from([1]), eph.der, iv, ct, c.getAuthTag()]);
  return PREFIX + kid + '.' + b64u(payload);
}

// ---- 開始驗證 ----
let pass = 0, fail = 0;
const report = (ok, name, detail) => {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? '  → ' + detail : ''}`); }
};

console.log(`vectors: ${path.basename(file)}  protocol=${doc.protocol} v${doc.version}  alg=${doc.alg}\n`);

const keys = {};
for (const k of doc.keys) {
  const kp = keypair(k.d_hex);
  if (Buffer.from(k.spki_b64, 'base64').compare(kp.der) !== 0) throw new Error(`SPKI 不符：${k.kid}`);
  keys[k.kid] = kp;
}

console.log('[正向：解密]');
for (const v of doc.positive) {
  const expect = Buffer.from(v.plaintext_b64, 'base64');
  try {
    const got = decrypt(v.token, v.kid, v.purpose, keys[v.kid].priv);
    report(got.equals(expect), v.name, got.equals(expect) ? '' : '明文不一致');
  } catch (e) { report(false, v.name, e.code || e.message); }
}

console.log('\n[正向：固定隨機值重現密文]');
for (const v of doc.positive) {
  try {
    const token = encryptWith(keys[v.kid].der, v.kid, v.purpose, Buffer.from(v.plaintext_b64, 'base64'), Buffer.from(v.eph_d_hex, 'hex'), Buffer.from(v.iv_hex, 'hex'));
    report(token === v.token, v.name, token === v.token ? '' : '密文與向量不符（HKDF／AAD／佈局任一不一致）');
  } catch (e) { report(false, v.name, e.message); }
}

console.log('\n[負向：必須回傳指定錯誤碼]');
for (const n of doc.negative) {
  let got;
  if (!keys[n.kid]) got = 'ERR_UNKNOWN_KID';
  else {
    try { decrypt(n.token, n.kid, n.purpose, keys[n.kid].priv); got = 'OK'; }
    catch (e) { got = e.code || e.message; }
  }
  report(got === n.expect_error, n.name, got === n.expect_error ? '' : `預期 ${n.expect_error}，實際 ${got}`);
}

console.log(`\n結果：PASS ${pass} / FAIL ${fail}`);
process.exit(fail === 0 ? 0 : 1);
