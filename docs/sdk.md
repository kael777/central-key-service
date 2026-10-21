# SDK 對接指南

四種語言的 SDK 都在本倉庫內，行為一致：同一個協定、同一組錯誤碼、同一份測試向量。

## 目錄

- [共通概念](#共通概念)
- [Go](#go)
- [Java](#java)
- [PHP](#php)
- [Node.js](#nodejs)
- [常見坑](#常見坑)

---

## 共通概念

每個 SDK 分兩層：

| 層 | 作用 | 是否連網 |
|---|---|---|
| 純函式（crypto） | 加解密、解析 token | 否 |
| Client | 輪詢 `/sync`、取得私鑰、快取、降級 | 是 |

業務程式只需要用 Client；寫工具或離線校驗時用純函式。

### 設定項

| 設定 | 說明 |
|---|---|
| `baseUrl` | 中央服務位址，例如 `https://key.example.com` |
| `systemCode` | 本系統代碼，必須與憑證 CN 相同 |
| `cert` / `key` | 用戶端憑證與私鑰（PEM） |
| `ca` | 伺服器憑證的 CA。**公網用公開 CA 時留空**（走系統信任庫） |

### 行為

- 輪詢間隔 30 秒，快照有效期 60 秒
- `purpose` 必須與加密時一致
- 中央不可用超過 60 秒 → `ERR_STALE`，**不會退回明文**
- 未知版本先強制刷新一次，仍未知才報錯

---

## Go

```go
import "example.com/key-sdk/keyclient"

c, err := keyclient.New(keyclient.Config{
    BaseURL:    "https://key.example.com",
    SystemCode: "SYS-A",
    ClientCert: "/etc/key-sdk/clients/SYS-A.crt",
    ClientKey:  "/etc/key-sdk/clients/SYS-A.key",
    CAFile:     "", // 公網公開 CA 時留空
})
defer c.Close()

token, err := c.Encrypt(ctx, "SYS-B", "urlparam", []byte("a=1&b=2"))
plain, err := c.Decrypt(ctx, token, "urlparam")
```

純函式：

```go
token, _ := keycrypto.EncryptTo(spki, "SYS-B:3", "urlparam", plaintext)
pt, err := keycrypto.Decrypt(priv, token, "urlparam")
code := keycrypto.CodeOf(err)
```

範例程式：`go-key-sdk/examples/goclient`。

---

## Java

JDK 17+，零第三方依賴。

```java
KeyClient client = KeyClient.config()
    .baseUrl("https://key.example.com")
    .systemCode("SYS-A")
    .cert("/etc/key-sdk/clients/SYS-A.crt", "/etc/key-sdk/clients/SYS-A.key")
    // .ca("/path/ca.crt")  // 公開 CA 時不呼叫
    .build();

String token = client.encrypt("SYS-B", "urlparam", plaintext);
byte[] plain = client.decrypt(token, "urlparam");

try {
    // ...
} catch (KeyError e) {
    String code = e.code();   // ERR_AUTH ...
}
```

JDK 沒有 HKDF，SDK 內用 `Mac(HmacSHA256)` 實作；也沒有「私鑰標量 → 公鑰」API，測試用 `EcMath` 補上（生產路徑不經過）。

編譯與測試：

```bash
cd sdks/java
javac -encoding UTF-8 -d out $(find src -name '*.java')
javac -encoding UTF-8 -cp out -d out test/VectorTest.java
java -cp out VectorTest ../../key-protocol-vectors/v1/vectors.json
```

---

## PHP

PHP 8.1+，只需 `openssl` 與 `hash` 擴充。

```php
$client = new KeySdk\KeyClient([
    'base_url'    => 'https://key.example.com',
    'system_code' => 'SYS-B',
    'cert'        => '/etc/key-sdk/clients/SYS-B.crt',
    'key'         => '/etc/key-sdk/clients/SYS-B.key',
]);

$token = $client->encrypt('SYS-A', 'urlparam', $data);
$plain = $client->decrypt($token, 'urlparam');
```

**PHP 沒有常駐行程**，正式用法是 cron 每分鐘同步，業務請求只讀快取：

```
* * * * * php /opt/key-sdk/bin/key-sdk sync --config=/etc/key-sdk.php
```

```php
$cache = KeySdk\KeyCache::load('/var/cache/key-sdk/snapshot.json');
$plain = KeySdk\KeyCache::decrypt($cache, $token, 'urlparam');
```

`key-sdk check` 的離開碼：`0` 正常、`2` 快取過期、`3` 未授權、`4` 連線失敗。

---

## Node.js

Node 18+，只用內建模組。

```js
import { KeyClient } from '@cms/key-sdk';

const client = new KeyClient({
  baseUrl: 'https://key.example.com',
  systemCode: 'SYS-A',
  cert: '/etc/key-sdk/clients/SYS-A.crt',
  key: '/etc/key-sdk/clients/SYS-A.key',
});

const token = await client.encrypt('SYS-B', 'urlparam', Buffer.from('a=1&b=2'));
const plain = await client.decrypt(token, 'urlparam');
client.close();
```

純函式：

```js
import { encrypt, decrypt, parseToken } from '@cms/key-sdk/crypto';
```

---

## 常見坑

| 語言 | 坑 | 處理 |
|---|---|---|
| Java | 沒有內建 HKDF | SDK 已用 HMAC 實作 |
| Java | 沒有私鑰→公鑰 API | 僅測試路徑用 `EcMath` |
| PHP | `openssl_pkey_export()` 在 Windows 需要 openssl.cnf | SDK 不呼叫它 |
| PHP | 檔案帶 UTF-8 BOM 會讓 `declare(strict_types=1)` 失敗 | 存檔不加 BOM |
| Node | `Buffer.from(s,'base64url')` 會忽略非法字元 | SDK 先做字元檢查 |
| 全部 | purpose 不一致 → `ERR_AUTH` | 加密解密用同一個值 |
| 全部 | 用 Windows 內建 curl 帶 PEM 用戶端憑證 | 改用 goclient 或在 Linux 測試 |

## 互通性保證

四套 SDK 都通過同一份測試向量，且能在固定隨機值下產出**逐字元相同**的密文。
若你的實作跑不過向量，不要上線——那只會把問題延後到聯調階段。
