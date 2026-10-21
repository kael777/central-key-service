# Node.js SDK（cms-key v1）

Node 18+，只用 `node:crypto` 與內建 `https`。

## 驗證

```bash
npm test        # node test/vectors.mjs
```

實測：`PASS 24 / FAIL 0`。

## 使用

```js
import { KeyClient } from '@cms/key-sdk';

const client = new KeyClient({
  baseUrl: 'https://key.internal',
  systemCode: 'SYS-A',
  cert: '/etc/key-sdk/client.crt',
  key: '/etc/key-sdk/client.key',
  ca: '/etc/key-sdk/ca.crt',
});

const token = await client.encrypt('SYS-B', 'urlparam', Buffer.from('a=1&b=2'));
const pt = await client.decrypt(token, 'urlparam');
client.close();
```

只要純函式（不連中央）：

```js
import { encrypt, decrypt, parseToken } from '@cms/key-sdk/crypto';
```

錯誤以 `err.code` 取得，與其他語言一致。

## 注意

- `decrypt` 需要實際的私鑰物件；`KeyClient` 會自動取得並快取。
- `purpose` 必須與加密端一致，否則 AAD 不符會回 `ERR_AUTH`。
- 快照超過 60 秒且刷新失敗時，`encrypt` 回 `ERR_STALE`，**不會退回明文**。

端到端驗證（需先啟動中央服務）：

```bash
node test/client_smoke.mjs https://127.0.0.1:8443
```