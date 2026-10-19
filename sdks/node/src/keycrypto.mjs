// cms-key 協定 v1：純函式層（無網路、隨機源可注入）
import crypto from 'node:crypto';

export const PREFIX = 'KEY1.';
export const SPKI_LEN = 91;
export const IV_LEN = 12;
export const TAG_LEN = 16;
export const KEY_LEN = 32;
export const MAX_TOKEN_LEN = 8192;

const KID_RE = /^[A-Za-z0-9_:-]{1,64}$/;
const PURPOSE_RE = /^[a-z0-9_-]{1,32}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

export class KeyError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = 'KeyError';
    this.code = code;
  }
}

export const Code = Object.freeze({
  Format: 'ERR_FORMAT',
  UnknownKid: 'ERR_UNKNOWN_KID',
  Key: 'ERR_KEY',
  Auth: 'ERR_AUTH',
  Stale: 'ERR_STALE',
  Unavailable: 'ERR_UNAVAILABLE',
  Unauthorized: 'ERR_UNAUTHORIZED',
  PolicyDisabled: 'ERR_POLICY_DISABLED',
});

export function validKid(kid) {
  return typeof kid === 'string' && KID_RE.test(kid);
}

export function validPurpose(purpose) {
  return typeof purpose === 'string' && PURPOSE_RE.test(purpose);
}

function aad(kid, purpose) {
  return Buffer.concat([Buffer.from(kid, 'utf8'), Buffer.from([0]), Buffer.from(purpose, 'utf8')]);
}

function deriveKey(shared, kid, purpose) {
  return Buffer.from(
    crypto.hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.from(`cms-key-v1|${kid}|${purpose}`, 'utf8'), KEY_LEN)
  );
}

/** 由 32 bytes 私鑰純量建立 {d, x, y, keyObject} */
export function privateFromScalar(d) {
  if (!Buffer.isBuffer(d) || d.length !== KEY_LEN) throw new KeyError(Code.Key, '私鑰需為 32 bytes');
  const ecdh = crypto.createECDH('prime256v1');
  try {
    ecdh.setPrivateKey(d);
  } catch (e) {
    throw new KeyError(Code.Key, `私鑰純量非法：${e.message}`);
  }
  const pub = ecdh.getPublicKey(); // 65 bytes 未壓縮
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: pub.subarray(1, 33).toString('base64url'),
    y: pub.subarray(33, 65).toString('base64url'),
  };
  return {
    d,
    jwk,
    keyObject: crypto.createPrivateKey({ key: { ...jwk, d: d.toString('base64url') }, format: 'jwk' }),
    spki: crypto.createPublicKey({ key: jwk, format: 'jwk' }).export({ type: 'spki', format: 'der' }),
  };
}

/** 由 SPKI DER 建立公鑰物件 */
export function publicFromSPKI(spki) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec') throw new Error('不是 EC 金鑰');
    const jwk = key.export({ format: 'jwk' });
    if (jwk.crv !== 'P-256') throw new Error(`曲線為 ${jwk.crv}`);
    return key;
  } catch (e) {
    throw new KeyError(Code.Key, `SPKI 解析失敗：${e.message}`);
  }
}

/** 結構解析，不接觸金鑰 */
export function parseToken(token) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LEN) {
    throw new KeyError(Code.Format, 'token 型別或長度不合法');
  }
  if (!token.startsWith(PREFIX)) throw new KeyError(Code.Format, '缺少前綴');
  const rest = token.slice(PREFIX.length);
  const i = rest.indexOf('.');
  if (i <= 0) throw new KeyError(Code.Format, 'kid 分隔錯誤');
  const kid = rest.slice(0, i);
  const body = rest.slice(i + 1);
  if (!validKid(kid)) throw new KeyError(Code.Format, `kid 非法：${kid}`);
  if (!B64URL_RE.test(body)) throw new KeyError(Code.Format, 'payload 含非法字元');

  const payload = Buffer.from(body, 'base64url');
  if (payload.length < 1 + SPKI_LEN + IV_LEN + TAG_LEN) throw new KeyError(Code.Format, 'payload 過短');
  if (payload[0] !== 1) throw new KeyError(Code.Format, `未知版本位元組 0x${payload[0].toString(16)}`);

  let off = 1;
  const spki = payload.subarray(off, off + SPKI_LEN);
  off += SPKI_LEN;
  const iv = payload.subarray(off, off + IV_LEN);
  off += IV_LEN;
  return { kid, spki, iv, ciphertext: payload.subarray(off) };
}

/**
 * 加密。ephD／iv 供測試注入固定隨機值；生產環境請留空。
 */
export function encryptWith(spkiDer, kid, purpose, plaintext, ephD = null, iv = null) {
  if (!validKid(kid)) throw new KeyError(Code.Format, `kid 非法：${kid}`);
  if (!validPurpose(purpose)) throw new KeyError(Code.Format, `purpose 非法：${purpose}`);

  const recipient = publicFromSPKI(spkiDer);
  const eph = ephD ? privateFromScalar(ephD) : generate();

  let shared;
  try {
    shared = crypto.diffieHellman({ privateKey: eph.keyObject, publicKey: recipient });
  } catch (e) {
    throw new KeyError(Code.Key, `ECDH 失敗：${e.message}`);
  }
  const key = deriveKey(shared, kid, purpose);

  if (iv == null) iv = crypto.randomBytes(IV_LEN);
  if (iv.length !== IV_LEN) throw new KeyError(Code.Format, 'IV 需為 12 bytes');

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(kid, purpose));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();

  const payload = Buffer.concat([Buffer.from([1]), eph.spki, iv, ct, tag]);
  return PREFIX + kid + '.' + payload.toString('base64url');
}

export function encrypt(spkiDer, kid, purpose, plaintext) {
  return encryptWith(spkiDer, kid, purpose, plaintext, null, null);
}

/** 解密。purpose 必須與加密時一致。 */
export function decrypt(privateKey, token, purpose) {
  if (!validPurpose(purpose)) throw new KeyError(Code.Format, `purpose 非法：${purpose}`);
  const priv = normalizePrivate(privateKey);
  const t = parseToken(token);

  const ephPub = publicFromSPKI(t.spki);
  let shared;
  try {
    shared = crypto.diffieHellman({ privateKey: priv.keyObject, publicKey: ephPub });
  } catch (e) {
    throw new KeyError(Code.Key, `ECDH 失敗：${e.message}`);
  }
  const key = deriveKey(shared, t.kid, purpose);

  const ct = t.ciphertext;
  const tag = ct.subarray(ct.length - TAG_LEN);
  const body = ct.subarray(0, ct.length - TAG_LEN);

  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, t.iv);
    d.setAAD(aad(t.kid, purpose));
    d.setAuthTag(tag);
    return Buffer.concat([d.update(body), d.final()]);
  } catch {
    throw new KeyError(Code.Auth, 'GCM 認證失敗');
  }
}

function normalizePrivate(p) {
  if (Buffer.isBuffer(p)) return privateFromScalar(p);
  if (p && p.keyObject) return p;
  if (p && p.type === 'private') return { keyObject: p };
  throw new KeyError(Code.Key, '私鑰格式不支援');
}

function generate() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return privateFromScalar(ecdh.getPrivateKey());
}
