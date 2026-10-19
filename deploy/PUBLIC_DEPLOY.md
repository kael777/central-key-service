# 外網部署（公網 mTLS）

A／B 機器在外網，透過 443 連到伺服器。伺服器憑證用公開 CA，用戶端憑證用自家 CA。

## 0. 拓撲與握手

```
   A 機器 (10.1.1.11)                     B 機器 (10.1.1.12)
        │                                       │
        └────────────── 公網 443 ───────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Nginx (443)     │
                    │  伺服器憑證：公開CA │
                    │  用戶端CA：自家CA   │
                    └─────────┬─────────┘
                              │ 127.0.0.1:8443
                    ┌─────────▼─────────┐
                    │  中央 KEY 服務     │
                    └─────────┬─────────┘
                              │ 127.0.0.1:3306
                    ┌─────────▼─────────┐
                    │      MySQL        │
                    └───────────────────┘
```

一次 `/api/v1/sync` 的握手：

```
A                        Nginx                      後端
│── ClientHello ─────────▶│
│◀─ ServerHello + 伺服器憑證│         （A 驗證：公開 CA 簽的，主機名相符）
│── 用戶端憑證 ───────────▶│
│                         │ 驗證：自家 CA 簽的？吊銷了嗎？
│                         │ 取 CN = SYS-A
│                         │── X-Client-CN: SYS-A ──▶│
│                         │── X-Client-Verify ─────▶│
│                         │── X-Proxy-Secret ──────▶│ 驗證密鑰
│                         │                         │ 查系統存在？IP 白名單？
│◀──────── 200 快照 JSON ──┴─────────────────────────│
```

任何一步失敗 → 403，不會進到後端。

## 1. 伺服器準備

```bash
sudo useradd -r -s /usr/sbin/nologin key-svc
sudo mkdir -p /opt/central-key-service/{bin,certs}
sudo mkdir -p /etc/central-key /var/lib/central-key /var/log/central-key
sudo chown -R key-svc:key-svc /opt/central-key-service /var/lib/central-key /var/log/central-key
```

安裝 MySQL（略），建立資料庫與專用帳號：

```sql
CREATE DATABASE cms_key DEFAULT CHARACTER SET utf8mb4;
CREATE USER 'cmskey'@'127.0.0.1' IDENTIFIED BY '<強密碼>';
GRANT ALL PRIVILEGES ON cms_key.* TO 'cmskey'@'127.0.0.1';
FLUSH PRIVILEGES;
```

## 2. 編譯與上傳

**Windows**（在 repo 根目錄）：

```bat
scripts\build-linux.bat            :: linux/amd64
scripts\build-linux.bat arm64      :: linux/arm64
```

產出 `go-key-sdk\dist\linux-amd64\`。

上傳：

```powershell
scp -r go-key-sdk\dist\linux-amd64\* user@server:/opt/central-key-service/bin/
```

伺服器上：

```bash
chmod +x /opt/central-key-service/bin/*
```

**Linux** 直接編譯也可以：

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/central ./cmd/central
```

## 3. 憑證

### 3.1 伺服器憑證（公開 CA）

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d key.example.com
```

或手動放：

```
/etc/letsencrypt/live/key.example.com/fullchain.pem
/etc/letsencrypt/live/key.example.com/privkey.pem
```

### 3.2 用戶端 CA 與 A／B 憑證

用專案自帶工具（適合測試）：

```bash
cd /opt/central-key-service
./bin/devca -out ./certs -systems SYS-A,SYS-B
```

產生：

| 檔案 | 用途 |
|---|---|
| `certs/ca.crt` / `ca.key` | 用戶端 CA（**ca.key 必須離線保管**） |
| `certs/clients/SYS-A.crt` / `.key` | 給 A |
| `certs/clients/SYS-B.crt` / `.key` | 給 B |

> 正式環境建議用公司既有 CA 簽發，憑證有效期 ≤ 1 年，並納入吊銷流程。

### 3.3 分發

| 檔案 | 給誰 | 放哪 |
|---|---|---|
| `SYS-A.crt` / `SYS-A.key` | 只給 A | `/etc/key-sdk/clients/` |
| `SYS-B.crt` / `SYS-B.key` | 只給 B | `/etc/key-sdk/clients/` |

私鑰權限 `600`，屬主為執行服務的帳號。**不要走聊天工具傳**。

公網部署時 A／B **不需要** `ca.crt`——伺服器憑證是公開 CA 簽的，作業系統自帶。

## 4. 後端設定

`/etc/central-key/config.json`：

```json
{
  "addr": "127.0.0.1:8443",
  "cert": "certs/server.crt",
  "key": "certs/server.key",
  "ca": "certs/ca.crt",
  "admin_user": "admin",
  "admin_token": "<隨機長字串>",
  "api_token": "<另一個隨機長字串>",
  "session_secret": "<第三個隨機長字串>",
  "admin_cidr": ["10.20.0.0/16"],
  "trusted_proxies": ["127.0.0.1/32"],
  "proxy_secret": "<與 Nginx 相同>",
  "dsn": "cmskey:<密碼>@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC&charset=utf8mb4",
  "data": "/var/lib/central-key/state.json",
  "audit": "/var/log/central-key/audit.jsonl",
  "grace": "5m",
  "rotation": "720h"
}
```

`/etc/central-key/env`（0600）：

```
KEY_KEK=<openssl rand -hex 32 的輸出>
```

注意：`ca` 是**伺服器端用來驗證用戶端**的 CA（自家 CA），不是公開 CA。

## 5. systemd

```bash
sudo cp deploy/systemd/central-key.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now central-key
sudo systemctl status central-key
curl -sS --cacert /opt/central-key-service/certs/server.crt https://127.0.0.1:8443/healthz
```

## 6. Nginx

```bash
sudo cp deploy/nginx/central-key-public.conf /etc/nginx/conf.d/
sudo cp deploy/nginx/proxy-headers.conf /etc/nginx/snippets/central-key-headers.conf
sudo vi /etc/nginx/conf.d/central-key-public.conf   # 改 server_name 與路徑
sudo vi /etc/nginx/snippets/central-key-headers.conf # 改 X-Proxy-Secret
sudo nginx -t && sudo systemctl reload nginx
```

要改的點：

| 項目 | 改成 |
|---|---|
| `server_name` | 你的網域 |
| `ssl_certificate` | Let's Encrypt 路徑 |
| `ssl_client_certificate` | `/opt/central-key-service/certs/ca.crt` |
| `X-Proxy-Secret` | 與後端 `proxy_secret` 一致 |
| `limit_req` | 依流量調整 |

## 7. 防火牆

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

確認 8443 與 3306 對外不可達：

```bash
nmap -p 8443,3306 key.example.com    # 應為 filtered/closed
```

## 8. 登記 A／B

管理入口不放公網，從 VPN 或內網主機執行：

```bash
curl -s https://key.example.com/api/v1/admin/systems \
  -H "X-Admin-Token: $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"SYS-A","name":"A 機器"}'

curl -s https://key.example.com/api/v1/admin/systems \
  -H "X-Admin-Token: $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"SYS-B","name":"B 機器"}'
```

> 公網不要設 `ip_allow`：NAT／動態 IP 會讓它失效。身分靠憑證。

## 9. A／B 機器

### 9.1 Go

```bash
cd /opt/go-key-sdk
go run ./examples/goclient \
  -base https://key.example.com \
  -certs /etc/key-sdk \
  -system SYS-A -peer SYS-B \
  -data "訂單=A123"
```

`-certs` 目錄：

```
/etc/key-sdk/
└── clients/
    ├── SYS-A.crt
    └── SYS-A.key
```

（沒有 `ca.crt` 就用系統信任庫；若你們仍用自簽 CA，把 `ca.crt` 放進 `/etc/key-sdk/` 即可。）

### 9.2 其他語言

| 語言 | 設定 |
|---|---|
| Node | `{ cert, key, ca: undefined }`（不傳 ca 即用系統信任） |
| Java | `.cert(crt,key)`，`.ca()` 不呼叫即用 JVM 預設信任庫 |
| PHP | `'cert'=>...,'key'=>...`，`ca` 可省略 |

### 9.3 驗證

```bash
# 無憑證：應 403
curl -s https://key.example.com/api/v1/sync

# 有憑證：應 200
curl -s --cert /etc/key-sdk/clients/SYS-A.crt --key /etc/key-sdk/clients/SYS-A.key \
     https://key.example.com/api/v1/sync
```

## 10. 憑證續期與吊銷

**續期**：Let's Encrypt 自動續；用戶端憑證需自建排程，到期前 30 天告警。

**吊銷**（機器遺失／被入侵）：

```bash
# 1) 產生/更新 CRL（依你們 CA 工具）
openssl ca -revoke certs/clients/SYS-A.crt
openssl ca -gencrl -out certs/client-ca.crl

# 2) Nginx 啟用
# ssl_crl /opt/central-key-service/certs/client-ca.crl;

sudo nginx -s reload
```

同時在後台**停用該系統**（作廢金鑰），雙保險。

## 11. 排障

| 現象 | 原因 | 查什麼 |
|---|---|---|
| 403 且 Nginx log 顯示 `verify:NONE` | 請求沒帶憑證 | 客戶端 `cert`/`key` 路徑 |
| 403 且 `verify:FAILED:unable to verify the first certificate` | 憑證不是同一 CA 簽的 | `ssl_client_certificate` 是否為簽發 A/B 的 CA |
| 401 | Nginx 沒傳 `X-Client-CN` 或 secret 不符 | `proxy-headers.conf` 與後端 `proxy_secret` |
| 連接被重置 | 協議／端口不符 | 確認 443 且 SNI 正確 |
| `certificate has expired` | 憑證過期 | `openssl x509 -enddate -noout -in SYS-A.crt` |
| 輪詢忽然失敗 | 憑證被吊銷／換 CA | CRL、CA 是否更新 |

Nginx 記錄客戶端 CN 便於排查：

```nginx
log_format key '$remote_addr "$ssl_client_s_dn_cn" $ssl_client_verify $request $status';
access_log /var/log/nginx/central-key.access.log key;
```

## 12. 上線前檢查

- [ ] 公網只開 443；8443、3306 不可達
- [ ] `/admin`、`/login` 從公網回 403
- [ ] 無憑證請求 403
- [ ] A 用 B 的憑證 → 403
- [ ] 後台停用 B → B 取私鑰 403
- [ ] 輪替後新版本生效、舊版 5 分鐘後失效
- [ ] 伺服器憑證自動續期已驗證
- [ ] CRL 流程演練過一次
- [ ] 審計日誌能看到具體使用者與來源 IP
