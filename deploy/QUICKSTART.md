# 快速上手（照抄即可）

目標：**A 機器加密 → B 機器解密**，走公網，中央只發鑰匙。

全程約 30 分鐘。每步都有「看到這個才算過」，卡住就看最後一節。

---

## 0. 你需要

| 東西 | 備註 |
|---|---|
| 一台公網伺服器 | 有網域、443 可通、裝了 MySQL |
| A、B 兩台機器 | 能連外網，能放憑證檔與 `goclient` 執行檔 |
| Windows 開發機 | 編譯用 |
| 你的辦公 IP | 用來開後台 |

---

## 1. 編譯（Windows）

```bat
cd D:\work\work\kenny\other\rick1
go-key-sdk\scripts\build-linux.bat
```

✅ **看到這個才算過**

```
=== result ===
central
dbsetup
devca
goclient
smoke
vectorcheck
```

---

## 2. 上傳（一次就好）

編譯產物已經包含 `central.sh` 與 `config.example.json`，整個資料夾傳上去即可：

```powershell
scp -r go-key-sdk\dist\linux-amd64\* root@伺服器:/opt/central-key-service/
```

```bash
cd /opt/central-key-service
chmod +x central central.sh
cp config.example.json config.json
mkdir -p certs /var/lib/central-key /var/log/central-key
```

目錄是扁平的，沒有 bin/、scripts/ 子層：

```
/opt/central-key-service/
├── central  dbsetup  devca  smoke  goclient  vectorcheck
├── central.sh
├── config.json
├── env
├── certs/
├── run/  logs/
└── DEPLOY.txt
```

---


## 3. 建資料庫

```bash
cd /opt/central-key-service
./dbsetup -dsn 'root:你的密碼@tcp(127.0.0.1:3306)/' -db cms_key
```

> DSN 一律用單引號：密碼含 `$`、`!` 或反引號時，雙引號會被 shell 展開（例如 `$*` 變成空），結果就是 `Access denied`。

✅ **看到這個才算過**

```
完成：資料庫 cms_key 與資料表已就緒
```

建議另建專用帳號（可選）：

```sql
CREATE USER 'cmskey'@'127.0.0.1' IDENTIFIED BY '強密碼';
GRANT ALL PRIVILEGES ON cms_key.* TO 'cmskey'@'127.0.0.1';
```

---

## 4. 產生憑證

### 4.1 伺服器憑證（給 Nginx 對外用）

```bash
certbot --nginx -d 你的網域
```

這一步做三件事：驗證網域所有權 → 簽發憑證 → 改 Nginx 並 reload。
**網域要換成你自己的**，且 DNS 必須指向這台伺服器、80 埠要能連。

> 用寶塔面板的話**跳過這步**：面板「SSL → Let's Encrypt」申請即可，路徑見 `deploy/BAOTA.md`。
> 沒有網域（只用 IP 測試）也跳過，改用第 4.2 步的自簽伺服器憑證，但 A/B 就必須手動信任 `ca.crt`。

### 4.2 用戶端 CA + A/B 憑證 + 後端自簽憑證

```bash
cd /opt/central-key-service
./devca -out ./certs -systems SYS-A,SYS-B
```

✅ **看到這個才算過**

```
完成：./certs
  ca.crt / ca.key              CA
  server.crt / server.key      伺服器憑證
  clients/                     2 個系統憑證
```

三個東西各有用途：

| 檔案 | 用途 |
|---|---|
| `certs/server.crt` / `.key` | 後端自己對 Nginx 的 TLS（loopback） |
| `certs/ca.crt` | 驗證 A/B 的用戶端憑證 |
| `certs/clients/SYS-*.crt` / `.key` | 給 A、B 的身分 |

---

## 5. 後端設定

先建目錄（少了這步，寫 `/opt/central-key-service/env` 會報 No such file or directory）：

```bash
mkdir -p /var/lib/central-key /var/log/central-key
```

編輯 `/opt/central-key-service/config.json`（第 2 步已從範例複製）：

```json
{
  "addr": "127.0.0.1:8443",
  "cert": "/opt/central-key-service/certs/server.crt",
  "key": "/opt/central-key-service/certs/server.key",
  "ca": "/opt/central-key-service/certs/ca.crt",
  "admin_user": "admin",
  "admin_token": "換成隨機長字串",
  "api_token": "換成另一個隨機長字串",
  "admin_cidr": ["127.0.0.1/32", "你的辦公IP/32"],
  "trusted_proxies": ["127.0.0.1/32"],
  "proxy_secret": "換成隨機字串，Nginx 要一樣",
  "dsn": "cmskey:強密碼@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC&charset=utf8mb4",
  "data": "/var/lib/central-key/state.json",
  "audit": "/var/log/central-key/audit.jsonl",
  "grace": "5m",
  "rotation": "720h"
}
```

產生金鑰（只做一次，**之後不能換**）：

```bash
echo "KEY_KEK=$(openssl rand -hex 32)" > /opt/central-key-service/env
chmod 600 /opt/central-key-service/env
cat /opt/central-key-service/env     # 確認有寫進去
```

**KEY_KEK 是什麼**：一把「包私鑰的鑰匙」。每個系統的私鑰寫進資料庫前，會先用它做 AES-256-GCM 加密；
所以資料庫被拖走，沒有 KEY_KEK 也解不開任何私鑰。它只存在 `/opt/central-key-service/env`，不進資料庫；
**換掉它，舊私鑰就全部解不開**。


---

## 6. 啟動

一條命令（背景執行，自動讀 `/opt/central-key-service/env` 與 `/opt/central-key-service/config.json`）：

```bash
cd /opt/central-key-service
./central.sh start
```

腳本做的事：載入 `KEY_KEK` → 啟動 `central` → 寫 PID 到 `run/central.pid` → 日誌寫 `logs/central.log` → 打一次 `/healthz`。

✅ **看到這個才算過**

```
starting with config: /opt/central-key-service/config.json
started (pid 12345), log: /opt/central-key-service/logs/central.log
{"status":"ok","store":"mysql:tcp(127.0.0.1:3306)/cms_key"}
```

其他常用：

```bash
./central.sh status     # 是否在跑 + healthz
./central.sh logs       # tail -f
./central.sh restart
./central.sh stop
./central.sh check      # 只打 healthz
```

設定檔預設找**程式目錄**的 `config.json`；也可以用參數指定：`./central.sh start --config /path/config.json`。
想交給 systemd 管理的話，見 `deploy/systemd/central-key.service`。

---

## 7. Nginx

```bash
cp deploy/nginx/central-key-public.conf /etc/nginx/conf.d/
cp deploy/nginx/proxy-headers.conf /etc/nginx/snippets/central-key-headers.conf
```

要改的只有三處：

| 位置 | 改成 |
|---|---|
| `central-key-public.conf` 的 `server_name` | 你的網域 |
| 同檔的 `ssl_certificate` / `ssl_certificate_key` | certbot 產生的路徑 |
| `proxy-headers.conf` 的 `X-Proxy-Secret` | 與 `config.json` 的 `proxy_secret` 相同 |

```bash
nginx -t && systemctl reload nginx
```

✅ **看到這個才算過**

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://key.example.com/api/v1/sync
# 403   ← 沒帶憑證被擋，正確
```

---

## 8. 後台登記 A、B

公網版 Nginx **不開放後台**（`/admin` 直接 403）。兩種進入方式：

**方式 A：SSH 隧道（測試最省事）**

```bash
# 在你的電腦上
ssh -L 8443:127.0.0.1:8443 root@伺服器
```

瀏覽器開 `https://127.0.0.1:8443/admin`（憑證警告點繼續）。
需要 `admin_cidr` 含 `127.0.0.1/32`。

**方式 B：VPN + Nginx 放行**

把 `central-key-public.conf` 裡那段改成：

```nginx
location ~ ^/(admin|login|auth|logout) {
    allow 10.20.0.0/16;   # 你的辦公網段
    allow 127.0.0.1;
    deny  all;
    proxy_pass https://central_key_backend;
    include /etc/nginx/snippets/central-key-headers.conf;
}
```

帳號 `admin`，密碼是 `admin_token`。

點「新增系統」，填兩個：

| 代碼 | 名稱 |
|---|---|
| `SYS-A` | A 機器 |
| `SYS-B` | B 機器 |

✅ **看到這個才算過**：列表出現兩行，右上角綠色提示「已建立系統 SYS-A」。

> 後台只產生「加解密金鑰」。A/B 連線用的憑證是第 4 步 `devca` 產的，兩者不同。

---

## 9. 把憑證給 A、B

```bash
# 從伺服器
scp certs/clients/SYS-A.crt certs/clients/SYS-A.key A機器:/etc/key-sdk/clients/
scp certs/clients/SYS-B.crt certs/clients/SYS-B.key B機器:/etc/key-sdk/clients/
```

```bash
chmod 600 /etc/key-sdk/clients/*.key
```

公網部署**不需要**給 `ca.crt`（伺服器憑證是公開 CA 簽的）。

---

## 10. 在 A、B 上跑

**A 加密**

```bash
cd /opt/central-key-service
./goclient -base https://key.example.com -certs /etc/key-sdk \
  -system SYS-A -peer SYS-B -data "訂單=A123"
```

✅ **看到這個才算過**

```
KEY1.SYS-B:1.ATBZMBMGByq...
```

複製整串到 B。

**B 解密**

```bash
./goclient -base https://key.example.com -certs /etc/key-sdk \
  -system SYS-B -token "KEY1.SYS-B:1.ATBZMBMGByq..."
```

✅ **看到這個才算過**

```
訂單=A123
```

---

## 11. 驗收

| # | 做什麼 | 應該看到 |
|---|---|---|
| 1 | A 用自己的憑證加密 | 產出 token |
| 2 | B 用自己的憑證解密 | 明文一致 |
| 3 | B 改用 A 的憑證解密 | 403 |
| 4 | 後台按「停用 SYS-B」，B 再解密 | 403 |
| 5 | 後台按「立即輪替」，A 再加密 | token 變 `SYS-B:2`，5 分鐘內舊版仍可解 |

第 3 條最重要：**證明身分是憑證決定的。**

---

## 12. 跟 PM 對照

| PM 的要求 | 在那裡看 |
|---|---|
| 每系統專屬金鑰 | 後台「查看」→ 金鑰版本表 |
| 中央自動產生 | 新增系統後立刻有 `SYS-A:1` |
| 各系統自行加解密 | 第 10 步 |
| 5 分鐘緩衝 | 輪替後詳情頁：舊版 `decrypt_only`，5 分鐘後 `retired` |
| 停用即失效 | 第 11 步第 4 條 |
| 後台只有一頁 | `/admin`，加詳情頁與編輯 |

---

## 13. 卡住看這裡

| 症狀 | 原因 | 解法 |
|---|---|---|
| 502 / 連不上 | Nginx upstream 用 http 連 TLS 後端 | 確認 `proxy_pass https://...` |
| 所有 API 都 401 | Nginx 沒傳身分標頭 | 檢查 `X-Proxy-Secret` 與 `proxy_secret` 一致 |
| 403 且日誌 `verify:NONE` | A 沒帶憑證 | 檢查 `-certs` 路徑與檔名 |
| 後台 403 | `admin_cidr` 沒你的 IP | 加白名單或走 VPN |
| `permission denied` 私鑰 | 權限不對 | `chmod 600`，屬主正確 |
| 輪詢一直失敗 | 憑證不是同一 CA 簽的 | `ssl_client_certificate` 要用 `certs/ca.crt` |

查 Nginx 有沒有真的把憑證帶進來：

```bash
tail -f /var/log/nginx/error.log
# 看到 "client certificate: /CN=SYS-A" 就是對的
```

---

## 一句話

**編譯 → 建庫 → 產憑證 → 起服務 → 配 Nginx → 後台加 A/B → 發憑證 → 跑兩條命令。**

其他都是上線前的加固，不影響這條主線。
