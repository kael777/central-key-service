# 兩台機器（A/B）測試 SDK

目標：A 機器用 SYS-A 憑證加密，B 機器用 SYS-B 憑證解密，驗證 mTLS 身分、IP 白名單與版本機制。

```
        ┌──────────────┐
   A ──▶│  Nginx :443  │──▶ 中央服務 :8443 ──▶ MySQL
   B ──▶│  (mTLS)      │
        └──────────────┘
```

## 一、伺服器端準備

### 1. 產生憑證

```bash
cd /opt/go-key-sdk
go run ./cmd/devca -out ./certs -systems SYS-A,SYS-B
```

產出：

| 檔案 | 給誰 |
|---|---|
| `certs/ca.crt` | A、B 都要 |
| `certs/clients/SYS-A.crt` / `.key` | 只給 A |
| `certs/clients/SYS-B.crt` / `.key` | 只給 B |

> 私鑰用 scp/密碼管理系統傳，不要走聊天工具。

### 2. 啟動後端（Nginx 在後面時）

```bash
go run ./cmd/central \
  -addr 127.0.0.1:8443 \
  -cert certs/server.crt -key certs/server.key -ca certs/ca.crt \
  -admin-token "$ADMIN_TOKEN" \
  -trusted-proxy 127.0.0.1/32 \
  -proxy-secret "$PROXY_SECRET" \
  -admin-cidr 10.20.0.0/16 \
  -dsn "app:pass@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC"
```

`-trusted-proxy` 必須等於 Nginx 的來源位址，`-proxy-secret` 必須等於 `proxy-headers.conf` 裡的值。

### 3. 登記系統（帶 IP 白名單）

```bash
curl -s https://key.internal/api/v1/admin/systems \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"SYS-A","name":"A 機器","ip_allow":["10.1.1.11"]}'

curl -s https://key.internal/api/v1/admin/systems \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"SYS-B","name":"B 機器","ip_allow":["10.1.1.12"]}'
```

`ip_allow` 是**可選的第二道防線**；留空則不限制（僅測試用）。

## 二、A 機器：加密

把 `ca.crt` 放到 `/etc/key-sdk/`，`SYS-A.crt`、`SYS-A.key` 放到 `/etc/key-sdk/clients/`。

```bash
cd /opt/go-key-sdk
go run ./examples/goclient \
  -base https://key.internal \
  -certs /etc/key-sdk \
  -system SYS-A -peer SYS-B \
  -purpose urlparam \
  -data "訂單編號=A123456&金額=1000"
```

輸出即密文：

```
KEY1.SYS-B:1.ATBZMBMGByq...
```

把這串複製到 B。

## 三、B 機器：解密

```bash
cd /opt/go-key-sdk
go run ./examples/goclient \
  -base https://key.internal \
  -certs /etc/key-sdk \
  -system SYS-B \
  -token "KEY1.SYS-B:1.ATBZMBMGByq..."
```

應輸出 `訂單編號=A123456&金額=1000`。

> B 機器同理：`/etc/key-sdk/ca.crt` + `/etc/key-sdk/clients/SYS-B.{crt,key}`。\n> 注意 `-certs` 的目錄結構就是「ca.crt 在根目錄、憑證在 clients/ 子目錄」。
> 若想改成扁平結構，改 `examples/goclient` 的兩個路徑參數即可。

## 四、要驗的五件事

| # | 操作 | 預期 |
|---|---|---|
| 1 | A 用 SYS-A 憑證加密 | 成功，token 版本為 `SYS-B:1` |
| 2 | B 用 SYS-B 憑證解密 | 明文一致 |
| 3 | B 改用 SYS-A 的憑證去解 | 失敗（`ERR_UNAUTHORIZED` 或 403） |
| 4 | 後台停用 SYS-B，再解 | B 取不到私鑰（403） |
| 5 | 輪替 SYS-B 後重新加密 | token 變 `SYS-B:2`；5 分鐘內 `:1` 仍可解 |

第 3 條是關鍵：**證明身分是由憑證決定的，不是靠請求參數**。

## 五、Nginx 沒配對時的症狀

| 現象 | 原因 |
|---|---|
| A 連 `/api/v1/sync` 回 401 | Nginx 沒帶 `X-Client-CN`，或 `X-Proxy-Secret` 與後端不符 |
| 回 403 且日誌顯示 `$ssl_client_verify` 非 SUCCESS | A 沒帶憑證，或憑證不是同一 CA 簽的 |
| 後台 403 | `admin_cidr` 沒包含你的來源網段 |
| 連不上 | 後端只聽 127.0.0.1，必須經 Nginx；或防火牆沒開 443 |

## 六、沒有 Nginx 時

直接對後端做 mTLS 也可以（後端本身就是 TLS 服務）：

```bash
go run ./examples/goclient -base https://key.internal:8443 -certs /etc/key-sdk -system SYS-A -peer SYS-B -data hi
```

此時不要設 `-trusted-proxy`，後端會直接讀用戶端憑證。
