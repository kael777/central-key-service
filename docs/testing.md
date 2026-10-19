# 在另一台伺服器上測 SDK

前提：後台已登記 `SYS-A` / `SYS-B`，且 `devca` 已產生對應憑證。

## 1. 只需要複製兩樣東西

從中央伺服器：

```bash
# 執行檔（A/B 不需要裝 Go）
scp /opt/central-key-service/goclient user@A:/opt/keytest/goclient
scp /opt/central-key-service/goclient user@B:/opt/keytest/goclient

# 自己的憑證（只給自己的）
scp /opt/central-key-service/certs/clients/SYS-A.crt /opt/central-key-service/certs/clients/SYS-A.key user@A:/opt/keytest/clients/
scp /opt/central-key-service/certs/clients/SYS-B.crt /opt/central-key-service/certs/clients/SYS-B.key user@B:/opt/keytest/clients/
```

```bash
chmod +x /opt/keytest/goclient
chmod 600 /opt/keytest/clients/*.key
```

> 公網部署用公開 CA，**不需要** `ca.crt`；只有自簽伺服器憑證時才要複製並用 `-ca` 指定。

## 2. 目錄

```
/opt/keytest/
├── goclient
└── clients/
    ├── SYS-A.crt
    └── SYS-A.key
```

`goclient` 的 `-certs` 參數要指向**上一層**（`/opt/keytest`），它會自己找 `clients/<code>.crt`。

## 3. 先確認連得上

```bash
curl -s --cert /opt/keytest/clients/SYS-A.crt --key /opt/keytest/clients/SYS-A.key \
  https://key.example.com/api/v1/sync
```

應該回一段 JSON，內含 `self.decrypt_versions` 與 `peers`。

| 回應 | 意思 |
|---|---|
| JSON | 憑證與登記都正常 |
| `{"error":"缺少用戶端憑證"}` | 沒帶憑證，或後端沒設 `trusted_proxies` |
| `{"error":"來源 IP 不符"}` | 系統沒登記，或設了不匹配的允許 IP |
| nginx 403 | 憑證不是 Nginx 信任的 CA 簽的 |

## 4. A 機器：加密

```bash
/opt/keytest/goclient \
  -base https://key.example.com \
  -certs /opt/keytest \
  -system SYS-A \
  -peer SYS-B \
  -purpose urlparam \
  -data "訂單編號=A123456"
```

輸出：

```
KEY1.SYS-B:1.ATBZMBMGByq...
```

**複製整串**（含 `KEY1.`）到 B。

## 5. B 機器：解密

```bash
/opt/keytest/goclient \
  -base https://key.example.com \
  -certs /opt/keytest \
  -system SYS-B \
  -token "KEY1.SYS-B:1.ATBZMBMGByq..."
```

輸出：

```
訂單編號=A123456
```

## 6. 其他語言（同一台機器）

只要把憑證換成對應路徑，`ca` 留空即用系統信任庫。

**Node**

```js
const c = new KeyClient({ baseUrl: 'https://key.example.com', systemCode: 'SYS-A',
  cert: '/opt/keytest/clients/SYS-A.crt', key: '/opt/keytest/clients/SYS-A.key' });
const token = await c.encrypt('SYS-B', 'urlparam', Buffer.from('a=1&b=2'));
```

**Java**

```java
KeyClient c = KeyClient.config()
    .baseUrl("https://key.example.com")
    .systemCode("SYS-A")
    .cert("/opt/keytest/clients/SYS-A.crt", "/opt/keytest/clients/SYS-A.key")
    .build();
```

**PHP**

```php
$c = new KeySdk\KeyClient([
  'base_url' => 'https://key.example.com',
  'system_code' => 'SYS-A',
  'cert' => '/opt/keytest/clients/SYS-A.crt',
  'key'  => '/opt/keytest/clients/SYS-A.key',
]);
```

## 7. 驗收三條

| # | 操作 | 預期 |
|---|---|---|
| 1 | A 加密 | 得到 `KEY1.SYS-B:...` |
| 2 | B 解密 | 明文一致 |
| 3 | B 改用 A 的憑證去解 | 403 |

第 3 條證明身份由憑證決定。

## 8. 常見錯誤

| 錯誤 | 原因 |
|---|---|
| `ERR_UNAUTHORIZED` | 憑證 CN 與登記代碼不一致，或系統被停用 |
| `ERR_UNKNOWN_KID` | 版本號不存在（例如 token 來自別的環境） |
| `x509: certificate signed by unknown authority` | 自簽伺服器憑證但沒帶 `-ca` |
| `connection refused` | 位址或埠不對；公網只開 443 |

## 9. 換系統代碼要注意

`-system` 參數決定用哪張憑證、以及 `User-Agent`；**憑證的 CN 必須等於這個值**，否則後端認出來的是別人。
