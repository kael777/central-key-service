// 以 vectors.json 驗證 Node SDK：解密、密文重現、負向錯誤碼
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  Code,
  KeyError,
  decrypt,
  encryptWith,
  parseToken,
  privateFromScalar,
  SPKI_LEN,
} from '../src/keycrypto.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

function findVectors() {
  if (process.env.KEY_VECTORS) return process.env.KEY_VECTORS;
  let dir = here;
  for (let i = 0; i < 6; i++) {
    const p = path.join(dir, 'key-protocol-vectors', 'v1', 'vectors.json');
    if (fs.existsSync(p)) return p;
    dir = path.dirname(dir);
  }
  throw new Error('找不到 vectors.json，請設定 KEY_VECTORS');
}

const doc = JSON.parse(fs.readFileSync(findVectors(), 'utf8'));
let pass = 0;
let fail = 0;

function check(name, fn) {
  try {
    fn();
    pass++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    fail++;
    console.log(`  FAIL  ${name}  → ${e.message}`);
  }
}

const keys = new Map();
for (const k of doc.keys) {
  const priv = privateFromScalar(Buffer.from(k.d_hex, 'hex'));
  if (priv.spki.toString('base64') !== k.spki_b64) throw new Error(`SPKI 不符：${k.kid}`);
  keys.set(k.kid, priv);
}

console.log('[正向：解密]');
for (const v of doc.positive) {
  check(v.name, () => {
    const pt = decrypt(keys.get(v.kid), v.token, v.purpose);
    if (pt.toString('base64') !== v.plaintext_b64) throw new Error('明文不一致');
  });
}

console.log('\n[正向：固定隨機值重現密文]');
for (const v of doc.positive) {
  check(v.name, () => {
    const token = encryptWith(
      keys.get(v.kid).spki,
      v.kid,
      v.purpose,
      Buffer.from(v.plaintext_b64, 'base64'),
      Buffer.from(v.eph_d_hex, 'hex'),
      Buffer.from(v.iv_hex, 'hex')
    );
    if (token !== v.token) throw new Error('密文與向量不符');
  });
}

console.log('\n[負向：必須回傳指定錯誤碼]');
for (const n of doc.negative) {
  check(n.name, () => {
    const priv = keys.get(n.kid);
    if (!priv) {
      if (n.expect_error !== Code.UnknownKid) throw new Error(`預期 ${n.expect_error}`);
      return;
    }
    try {
      decrypt(priv, n.token, n.purpose);
    } catch (e) {
      if (e.code !== n.expect_error) throw new Error(`預期 ${n.expect_error}，實際 ${e.code}`);
      return;
    }
    throw new Error('預期錯誤但解密成功');
  });
}

console.log('\n[邊界：超長 token]');
check('oversize', () => {
  try {
    parseToken('KEY1.SYS-B:3.' + 'A'.repeat(9000));
  } catch (e) {
    if (e.code === Code.Format) return;
    throw new Error(`預期 ${Code.Format}，實際 ${e.code}`);
  }
  throw new Error('應拒絕');
});

console.log(`\n結果：PASS ${pass} / FAIL ${fail}`);
process.exit(fail === 0 ? 0 : 1);
