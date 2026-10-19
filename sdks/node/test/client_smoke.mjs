// 端到端驗證：A 加密 → B 解密，走真實 mTLS 與中央服務
import { fileURLToPath } from 'node:url';
import { KeyClient } from '../src/client.mjs';

const base = process.argv[2] ?? 'https://127.0.0.1:8443';
const certs = process.argv[3] ?? fileURLToPath(new URL('../../../go-key-sdk/certs', import.meta.url));

const mk = (code) =>
  new KeyClient({
    baseUrl: base,
    systemCode: code,
    cert: `${certs}/clients/${code}.crt`,
    key: `${certs}/clients/${code}.key`,
    ca: `${certs}/ca.crt`,
  });

const a = mk('SYS-A');
const b = mk('SYS-B');

try {
  const payload = Buffer.from('訂單編號=A123456&金額=1000', 'utf8');
  const token = await a.encrypt('SYS-B', 'urlparam', payload);
  console.log(`A encrypt → ${token.slice(0, 24)}...（${token.length} 字元）`);

  const plain = await b.decrypt(token, 'urlparam');
  console.log(`B decrypt → "${plain.toString('utf8')}"`);
  if (!plain.equals(payload)) throw new Error('明文不符');

  try {
    await b.decrypt(token, 'body');
    throw new Error('purpose 不符應該失敗');
  } catch (e) {
    if (e.code !== 'ERR_AUTH') throw new Error(`預期 ERR_AUTH，實際 ${e.code}`);
  }

  console.log(`snapshot A: mode=${a.snapshot.mode} peers=${a.snapshot.peers.size}`);
  if (!b.snapshot) await b.refresh();
  console.log(`snapshot B: decrypt_versions=${b.snapshot.decryptKIDs.size}`);
  console.log('PASS  Node Client 端到端成功');
  a.close();
  b.close();
} catch (e) {
  console.error(`FAIL: ${e.message}`);
  a.close();
  b.close();
  process.exit(1);
}
