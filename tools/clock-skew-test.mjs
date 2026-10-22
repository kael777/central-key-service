// 時鐘回撥對 SDK 快取的影響（Node）。
// 用法：node tools/clock-skew-test.mjs
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // 測試用自簽憑證

import { KeyClient } from '../sdks/node/src/index.mjs';

const base = 'https://127.0.0.1:9443';
const admin = { 'X-Admin-Token': 'tok' };

// 用 1 秒的快取上限，方便在短時間內觀察刷新行為
const client = new KeyClient({
  baseUrl: base,
  systemCode: 'SYS-A',
  cert: 'go-key-sdk/certs/clients/SYS-A.crt',
  key: 'go-key-sdk/certs/clients/SYS-A.key',
  ca: 'go-key-sdk/certs/ca.crt',
  maxStalenessMs: 1000,
});

const kidOf = (token) => token.split('.')[1];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function rotate(system) {
  const res = await fetch(`${base}/api/v1/admin/systems/${system}/rotate`, { method: 'POST', headers: admin });
  if (res.status !== 200) throw new Error(`rotate ${res.status}`);
  return (await res.json()).kid;
}

const realNow = Date.now;
let offset = 0;
Date.now = () => realNow() + offset;

const t1 = await client.encrypt('SYS-B', 'urlparam', Buffer.from('one'));
console.log('1) 初次加密 kid =', kidOf(t1));

const b2 = await rotate('SYS-B');
await sleep(1200);
offset = -3600_000;
const t2 = await client.encrypt('SYS-B', 'urlparam', Buffer.from('two'));
console.log(`2) 伺服器已輪替到 ${b2}，牆鐘回撥 1 小時、真實經過 1.2 秒`);
console.log('   加密使用 kid =', kidOf(t2), kidOf(t2) === b2 ? '→ 已刷新（不受回撥影響）' : '→ 仍是舊版（有風險）');

offset = 0;
client.close();
