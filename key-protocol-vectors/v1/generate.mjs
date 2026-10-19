// 產生並自我驗證 cms-key 協定 v1 測試向量
// 用法：node generate.mjs  → 覆寫同目錄 vectors.json
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PREFIX = 'KEY1.';
const VER = 1;
const SPKI_LEN = 91;   // P-256 SubjectPublicKeyInfo 固定長度
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

const b64u = (b) => Buffer.from(b).toString('base64url');
const hex = (b) => Buffer.from(b).toString('hex');
const infoBuf = (kid, purpose) => Buffer.from(`cms-key-v1|${kid}|${purpose}`, 'utf8');
const aadBuf = (kid, purpose) => Buffer.concat([Buffer.from(kid, 'utf8'), Buffer.from([0]), Buffer.from(purpose, 'utf8')]);

/** 由 32-byte 私鑰純量建立 KeyObject 與 SPKI DER */
function keyFromD(dHex) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(dHex, 'hex'));
  const pub = ecdh.getPublicKey();                    // 65 bytes 未壓縮點
  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: pub.subarray(1, 33).toString('base64url'),
    y: pub.subarray(33, 65).toString('base64url'),
  };
  const pubObj = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const privObj = crypto.createPrivateKey({ key: { ...jwk, d: b64u(Buffer.from(dHex, 'hex')) }, format: 'jwk' });
  const der = pubObj.export({ type: 'spki', format: 'der' });
  if (der.length !== SPKI_LEN) throw new Error(`SPKI 長度異常：${der.length}`);
  return { d: Buffer.from(dHex, 'hex'), der, pubObj, privObj };
}

function randomD() {
  const e = crypto.createECDH('prime256v1');
  e.generateKeys();
  return e.getPrivateKey();
}

function deriveKey(shared, kid, purpose) {
  const k = crypto.hkdfSync('sha256', shared, Buffer.alloc(0), infoBuf(kid, purpose), KEY_LEN);
  return Buffer.from(k);
}

function encryptFixed(recipientDer, kid, purpose, plaintext, ephD, iv) {
  const eph = keyFromD(ephD);
  const recipient = crypto.createPublicKey({ key: recipientDer, format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({ privateKey: eph.privObj, publicKey: recipient });
  const key = deriveKey(shared, kid, purpose);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aadBuf(kid, purpose));
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const tag = c.getAuthTag();
  const payload = Buffer.concat([Buffer.from([VER]), eph.der, iv, ct, tag]);
  return { token: PREFIX + kid + '.' + b64u(payload), keyHex: hex(key) };
}

function parseToken(token) {
  if (typeof token !== 'string') throw err('ERR_FORMAT');
  if (!token.startsWith(PREFIX)) throw err('ERR_FORMAT');
  const rest = token.slice(PREFIX.length);
  const dot = rest.indexOf('.');
  if (dot <= 0) throw err('ERR_FORMAT');
  const kid = rest.slice(0, dot);
  const body = rest.slice(dot + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(body)) throw err('ERR_FORMAT');
  const payload = Buffer.from(body, 'base64url');
  if (payload.length < 1 + SPKI_LEN + IV_LEN + TAG_LEN) throw err('ERR_FORMAT');
  if (payload[0] !== VER) throw err('ERR_FORMAT');
  return {
    kid,
    spki: payload.subarray(1, 1 + SPKI_LEN),
    iv: payload.subarray(1 + SPKI_LEN, 1 + SPKI_LEN + IV_LEN),
    ct: payload.subarray(1 + SPKI_LEN + IV_LEN, payload.length - TAG_LEN),
    tag: payload.subarray(payload.length - TAG_LEN),
  };
}

function decrypt(token, kid, purpose, privD) {
  const t = parseToken(token);
  if (t.kid !== kid) throw err('ERR_UNKNOWN_KID');
  let ephPub;
  try {
    ephPub = crypto.createPublicKey({ key: t.spki, format: 'der', type: 'spki' });
  } catch { throw err('ERR_KEY'); }
  const me = keyFromD(privD);
  let shared;
  try {
    shared = crypto.diffieHellman({ privateKey: me.privObj, publicKey: ephPub });
  } catch { throw err('ERR_KEY'); }
  const key = deriveKey(shared, kid, purpose);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, t.iv);
    d.setAAD(aadBuf(kid, purpose));
    d.setAuthTag(t.tag);
    return Buffer.concat([d.update(t.ct), d.final()]);
  } catch { throw err('ERR_AUTH'); }
}

function err(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}

// ---- 固定測試金鑰（僅供測試，不得用於任何環境） ----
const KEYS = [
  { kid: 'SYS-A:1', dHex: randomD().toString('hex') },
  { kid: 'SYS-B:3', dHex: randomD().toString('hex') },
].map((k) => {
  const kk = keyFromD(k.dHex);
  return { kid: k.kid, d_hex: k.dHex, spki_b64: Buffer.from(kk.der).toString('base64'), ...kk };
});

const keyByKid = Object.fromEntries(KEYS.map((k) => [k.kid, k]));

const POSITIVE_SPEC = [
  { name: 'urlparam-32b', kid: 'SYS-B:3', purpose: 'urlparam', plaintext: Buffer.from('a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&', 'utf8') },
  { name: 'urlparam-128b', kid: 'SYS-B:3', purpose: 'urlparam', plaintext: Buffer.alloc(128, 0x41) },
  { name: 'body-512b', kid: 'SYS-A:1', purpose: 'body', plaintext: Buffer.alloc(512, 0x5a) },
  { name: 'empty-plaintext', kid: 'SYS-A:1', purpose: 'body', plaintext: Buffer.alloc(0) },
  { name: 'utf8-zh', kid: 'SYS-B:3', purpose: 'urlparam', plaintext: Buffer.from('訂單編號=A123456&金額=1000&備註=測試', 'utf8') },
  { name: 'binary', kid: 'SYS-B:3', purpose: 'body', plaintext: Buffer.from(Array.from({ length: 64 }, (_, i) => (i * 37) & 0xff)) },
];

const positives = POSITIVE_SPEC.map((spec) => {
  const k = keyByKid[spec.kid];
  const ephD = randomD();
  const iv = crypto.randomBytes(IV_LEN);
  const { token, keyHex } = encryptFixed(k.der, spec.kid, spec.purpose, spec.plaintext, ephD, iv);
  return {
    name: spec.name,
    kid: spec.kid,
    purpose: spec.purpose,
    plaintext_b64: spec.plaintext.toString('base64'),
    eph_d_hex: ephD.toString('hex'),
    iv_hex: iv.toString('hex'),
    token,
    debug_hkdf_key_hex: keyHex,
  };
});

// ---- 自我驗證：正向 ----
for (const v of positives) {
  const k = keyByKid[v.kid];
  const out = decrypt(v.token, v.kid, v.purpose, k.d_hex);
  if (!out.equals(Buffer.from(v.plaintext_b64, 'base64'))) throw new Error(`正向失敗：${v.name}`);
}

// ---- 負向案例 ----
function mutToken(token, fn) {
  const [p, kid, body] = token.split('.');
  return `${p}.${kid}.${b64u(fn(Buffer.from(body, 'base64url')))}`;
}

const base = positives[0];
const basePayload = Buffer.from(base.token.split('.')[2], 'base64url');

const negatives = [];
const addNeg = (name, token, kid, purpose, expect, note) => negatives.push({ name, token, kid, purpose, expect_error: expect, note });

// 1. tag 篡改
{
  const p = Buffer.from(basePayload);
  p[p.length - 1] ^= 0x01;
  addNeg('tampered-tag', `${PREFIX}${base.kid}.${b64u(p)}`, base.kid, base.purpose, 'ERR_AUTH', 'GCM tag 最後一個 byte 反轉');
}
// 2. 密文篡改
{
  const p = Buffer.from(basePayload);
  const ctStart = 1 + SPKI_LEN + IV_LEN;
  p[ctStart + 2] ^= 0x80;
  addNeg('tampered-ciphertext', `${PREFIX}${base.kid}.${b64u(p)}`, base.kid, base.purpose, 'ERR_AUTH', '密文內容改動一 byte');
}
// 3. AAD 不符（purpose 不同）
addNeg('aad-purpose-mismatch', base.token, base.kid, 'body', 'ERR_AUTH', '以不同 purpose 解密，AAD 不符');
// 4. 前綴 kid 指向另一把已知金鑰
addNeg('kid-prefix-swapped', `${PREFIX}SYS-A:1.${base.token.split('.')[2]}`, 'SYS-A:1', base.purpose, 'ERR_AUTH', '把 SYS-B:3 的密文前綴改成 SYS-A:1');
// 5. 未知 kid
addNeg('unknown-kid', `${PREFIX}SYS-Z:9.${base.token.split('.')[2]}`, 'SYS-Z:9', base.purpose, 'ERR_UNKNOWN_KID', '前綴為未登記的 kid');
// 6. 截斷：長度仍達最小值 → 落在認證失敗
{
  const p = basePayload.subarray(0, basePayload.length - 10);
  addNeg('truncated-tag', `${PREFIX}${base.kid}.${b64u(p)}`, base.kid, base.purpose, 'ERR_AUTH', '去掉 10 bytes（仍長於最小長度），tag 位移導致認證失敗');
}
// 6b. 截斷至低於最小長度 → 格式錯誤
{
  const p = basePayload.subarray(0, 100);
  addNeg('truncated-too-short', `${PREFIX}${base.kid}.${b64u(p)}`, base.kid, base.purpose, 'ERR_FORMAT', 'payload 僅 100 bytes，低於 1+91+12+16=120');
}
// 7. 版本位元組錯誤
{
  const p = Buffer.from(basePayload); p[0] = 0x02;
  addNeg('bad-version-byte', `${PREFIX}${base.kid}.${b64u(p)}`, base.kid, base.purpose, 'ERR_FORMAT', '版本位元組改為 0x02');
}
// 8. 前綴錯誤
addNeg('bad-prefix', `KEY2.${base.token.split('.').slice(1).join('.')}`, base.kid, base.purpose, 'ERR_FORMAT', '前綴不是 KEY1.');
// 9. base64url 含非法字元
{
  const body = base.token.split('.')[2];
  addNeg('illegal-base64url', `${PREFIX}${base.kid}.${body.slice(0, -4)}****`, base.kid, base.purpose, 'ERR_FORMAT', 'payload 含 * 字元');
}
// 10. 公鑰不在曲線上（竄改點座標）
{
  const p = Buffer.from(basePayload);
  for (let i = 1 + 26; i < 1 + SPKI_LEN; i++) p[i] = 0x00;   // 去掉 ASN.1 標頭後的 65 bytes 全歸零
  addNeg('off-curve-point', `${PREFIX}${base.kid}.${b64u(p)}`, base.kid, base.purpose, 'ERR_KEY', '臨時公鑰全零，不在 P-256 曲線上');
}

// ---- 驗證每個負向案例確實得到預期錯誤 ----
for (const n of negatives) {
  let got = null;
  const k = keyByKid[n.kid];
  if (!k) {
    got = 'ERR_UNKNOWN_KID'; // 金鑰集內查無此 kid，等同 SDK 查表失敗
  } else {
    try {
      decrypt(n.token, n.kid, n.purpose, k.d_hex);
      got = 'OK';
    } catch (e) {
      got = e.code || e.message;
    }
  }
  if (got !== n.expect_error) throw new Error(`負向案例 ${n.name}：預期 ${n.expect_error}，實際 ${got}`);
}

const doc = {
  protocol: 'cms-key',
  version: 1,
  alg: 'ECIES-P256-HKDF-SHA256-AES-256-GCM',
  spec: {
    token_format: 'KEY1.{kid}.{base64url(payload)}',
    kid_rule: '不得包含 . 字元；格式建議 {systemCode}:{seq}',
    payload_layout: '0x01 | eph_spki_der(91) | iv(12) | ciphertext(N) | tag(16)',
    hkdf: { hash: 'SHA-256', salt: '', info: 'cms-key-v1|{kid}|{purpose}', out_len: 32 },
    aad: 'utf8(kid) + 0x00 + utf8(purpose)',
    spki_len: SPKI_LEN,
    iv_len: IV_LEN,
    tag_len: TAG_LEN,
  },
  error_codes: {
    ERR_FORMAT: '前綴錯誤、長度不足、版本位元組錯誤、base64url 非法',
    ERR_UNKNOWN_KID: 'kid 未登記或已退役，或前綴與金鑰不符',
    ERR_KEY: '公鑰無效或不在曲線上',
    ERR_AUTH: 'GCM 認證失敗（密文、tag、AAD 任一不符）',
  },
  keys: KEYS.map(({ kid, d_hex, spki_b64 }) => ({ kid, d_hex, spki_b64, note: '測試用金鑰，禁止用於任何環境' })),
  positive: positives,
  negative: negatives,
};

const out = path.join(path.dirname(fileURLToPath(import.meta.url)), 'vectors.json');
fs.writeFileSync(out, JSON.stringify(doc, null, 2) + '\n', 'utf8');
console.log(`OK  正向 ${positives.length} 組、負向 ${negatives.length} 組 → ${out}`);
