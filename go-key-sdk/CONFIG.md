# 設定檔說明

`config.json` 是 JSON，不支援註解。`config.example.json` 裡的 `_doc` 欄位會被忽略，可留可刪。

> `config.json` 已在 `.gitignore`（含 `config.local.json`、`*.pem`、`certs/`、`data/`），不會進版本庫；
> 只有 `config.example.json` 會被追蹤。提交時 pre-commit 鉤子也會擋下 `config.json`。

優先序：**命令列旗標 > 環境變數 `KEY_KEK` > 設定檔 > 內建預設**。

## 全部欄位

### 網路與憑證

| 欄位 | 預設 | 說明 |
|---|---|---|
| `addr` | `:8443` | 監聽位址。**正式環境填 `127.0.0.1:8443`**，只讓 Nginx 連 |
| `cert` / `key` | `certs/server.crt` / `.key` | 後端自己的 TLS 憑證（loopback 用，自簽即可） |
| `ca` | `certs/ca.crt` | 用來**驗證 A/B 用戶端憑證**的 CA（不是公開 CA） |

### 後台帳號

| 欄位 | 預設 | 說明 |
|---|---|---|
| `admin_user` | `admin` | 後台帳號 |
| `admin_token` | — | **必填**。後台密碼；權杖模式登入用 |
| `api_token` | 同 `admin_token` | 管理 API 的 `X-Admin-Token`。與網頁密碼分離用 |
| `session_secret` | 同 `admin_token` | 會話 cookie 簽章密鑰。洩漏時可單獨輪換 |

> 三者留空會回退到 `admin_token`。改了任一個，已登入的瀏覽器都會被踢出。

### 來源限制

| 欄位 | 預設 | 說明 |
|---|---|---|
| `admin_cidr` | `[]` | 後台允許網段。**空 = 不限制（僅測試）**。支援 `10.0.0.0/8`、`1.2.3.4/32` |
| `trusted_proxies` | `[]` | 受信反向代理網段，例如 `["127.0.0.1/32"]` |
| `proxy_secret` | 空 | 代理轉發身分標頭的共享密鑰，必須與 Nginx 的 `X-Proxy-Secret` 相同 |

> 走 Nginx 時這三項缺一不可；直連 mTLS 時全部留空。

### 儲存

| 欄位 | 預設 | 說明 |
|---|---|---|
| `dsn` | 空 | MySQL 連線字串。**非空時優先於 `data`** |
| `data` | 空 | JSON 狀態檔；留空為純記憶體（重啟即失） |
| `audit` | 空 | 稽核 JSONL；留空只保留記憶體 |
| `kek` | 空 | 主金鑰（64 位十六進位）。**建議留空，改用環境變數 `KEY_KEK`** |

`dsn` 範例：

```
cmskey:密碼@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC&charset=utf8mb4
```

### 輪替

| 欄位 | 預設 | 說明 |
|---|---|---|
| `grace` | `5m` | 舊版解密緩衝期。與 SDK 快取上限共同決定安全邊界，不建議調整 |
| `prepublish` | `10m` | 新公鑰提前下發的時間 |
| `rotation` | `1h` | 自動輪替週期（預設每小時） |

### SSO（可選）

| 欄位 | 說明 |
|---|---|
| `oidc.issuer` | IdP 的 issuer；**非空即啟用 SSO**，權杖登入會被關閉 |
| `oidc.client_id` / `client_secret` | IdP 註冊的用戶端 |
| `oidc.redirect_url` | 回呼網址，例 `https://key.example.com/auth/callback` |
| `oidc.username_claim` | 取使用者名稱的 claim，預設 `preferred_username` |
| `oidc.groups_claim` | 取群組的 claim，預設 `groups` |
| `oidc.default_role` | 未對應群組時的角色：`viewer` / `operator` / `admin` |
| `oidc.group_roles` | 群組→角色，例 `{"cms-admins":"admin","cms-ops":"operator"}` |

---

## 三種現成組合

### A. 本機測試（檔案儲存、不用 Nginx）

```json
{
  "addr": "127.0.0.1:8443",
  "cert": "certs/server.crt",
  "key": "certs/server.key",
  "ca": "certs/ca.crt",
  "admin_token": "dev-token",
  "data": "data/state.json",
  "audit": "data/audit.jsonl"
}
```

### B. 內網 + MySQL（直連 mTLS，無 Nginx）

```json
{
  "addr": "127.0.0.1:8443",
  "cert": "certs/server.crt",
  "key": "certs/server.key",
  "ca": "certs/ca.crt",
  "admin_token": "換成隨機長字串",
  "admin_cidr": ["10.20.0.0/16"],
  "dsn": "cmskey:密碼@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC&charset=utf8mb4",
  "data": "/var/lib/central-key/state.json",
  "audit": "/var/log/central-key/audit.jsonl"
}
```

### C. 公網 + Nginx（欄位最容易漏）

```json
{
  "addr": "127.0.0.1:8443",
  "cert": "/opt/central-key-service/certs/server.crt",
  "key": "/opt/central-key-service/certs/server.key",
  "ca": "/opt/central-key-service/certs/ca.crt",
  "admin_token": "換成隨機長字串",
  "api_token": "另一個隨機長字串",
  "admin_cidr": ["127.0.0.1/32", "10.20.0.0/16"],
  "trusted_proxies": ["127.0.0.1/32"],
  "proxy_secret": "與 Nginx 的 X-Proxy-Secret 相同",
  "dsn": "cmskey:密碼@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC&charset=utf8mb4",
  "data": "/var/lib/central-key/state.json",
  "audit": "/var/log/central-key/audit.jsonl"
}
```

---

## 常見錯誤

| 現象 | 原因 |
|---|---|
| 所有 API 401 | `trusted_proxies` 沒填，或 `proxy_secret` 與 Nginx 不一致 |
| 後台 403 | `admin_cidr` 不含你的來源 IP |
| 重啟後資料不見 | `data` 為空（記憶體模式），或 `dsn` 沒生效 |
| 改 KEK 後取私鑰 500 | KEK 與建立金鑰時不同，舊私鑰解不開 |
| 登入後立刻被踢 | `admin_token` 或 `session_secret` 被改動 |
| 後台看不到「新增系統」 | 目前角色是 `viewer`，需要 `admin` |

---

## 檢查設定是否正確

```bash
# 啟動後看日誌
儲存後端：mysql:tcp(127.0.0.1:3306)/cms_key    # 有 dsn 時
儲存後端：file:/var/lib/central-key/state.json # 沒 dsn 時

# 健康檢查會回報儲存後端
curl -sk https://127.0.0.1:8443/healthz
{"status":"ok","store":"mysql:..."}
```
