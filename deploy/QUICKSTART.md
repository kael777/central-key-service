# 快速上手（30 分鐘看到結果）

目標：**A 機器加密 → B 機器解密**，全程走公網，中央只發鑰匙、不碰資料。

## 你需要

- 一台公網伺服器（有網域、443 可通）
- A、B 兩台機器
- Windows 開發機（用來編譯）

---

## 第 1 步：編譯（Windows）

```bat
cd D:\work\work\kenny\other\rick1
go-key-sdk\scripts\build-linux.bat
```

**看到這個就算成功：**

```
=== result ===
central  dbsetup  devca  smoke  vectorcheck
```

產物在 `go-key-sdk\dist\linux-amd64\`。

---

## 第 2 步：上傳到伺服器

```powershell
scp -r go-key-sdk\dist\linux-amd64\* root@伺服器:/opt/central-key-service/bin/
```

```bash
chmod +x /opt/central-key-service/bin/*
```

---

## 第 3 步：產生兩套憑證

```bash
cd /opt/central-key-service

# ① 伺服器憑證（公開 CA）
certbot --nginx -d key.example.com

# ② 用戶端 CA + A/B 憑證（自家 CA）
./bin/devca -out ./certs -systems SYS-A,SYS-B
```

**看到這個就算成功：**

```
完成：./certs
  ca.crt / ca.key              CA
  server.crt / server.key      伺服器憑證
  clients/<CODE>.crt/.key      2 個系統憑證
```

---

## 第 4 步：啟動後端

```bash
export KEY_KEK=$(openssl rand -hex 32)
./bin/central -config /etc/central-key/config.json \
  -trusted-proxy 127.0.0.1/32 \
  -proxy-secret "change-me"
```

**看到這個就算成功：**

```
中央 KEY 服務：https://127.0.0.1:8443
儲存後端：mysql:tcp(127.0.0.1:3306)/cms_key
```

自檢：

```bash
curl -sk https://127.0.0.1:8443/healthz
# {"status":"ok","store":"mysql:..."}
```

---

## 第 5 步：Nginx

```bash
cp deploy/nginx/central-key-public.conf /etc/nginx/conf.d/
cp deploy/nginx/proxy-headers.conf /etc/nginx/snippets/central-key-headers.conf

# 改三個值：server_name、X-Proxy-Secret、ssl_client_certificate 路徑
vi /etc/nginx/conf.d/central-key-public.conf
vi /etc/nginx/snippets/central-key-headers.conf

nginx -t && systemctl reload nginx
```

**看到這個就算成功：**

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://key.example.com/api/v1/sync
# 403  ← 沒帶憑證，被擋住（正確）
```

---

## 第 6 步：後台登記 A、B

用 VPN 或內網開：

```
https://key.example.com/admin
```

登入（帳號 `admin`，密碼是 `admin_token`）→ 新增兩個系統：

| 代碼 | 名稱 |
|---|---|
| `SYS-A` | A 機器 |
| `SYS-B` | B 機器 |

**看到這個就算成功：** 列表出現兩行，右上角綠色提示「已建立系統 SYS-A」。

> 注意：後台只負責「登記＋產生金鑰」，**不產生 A/B 的憑證檔**。憑證是第 3 步 `devca` 產的。

---

## 第 7 步：把憑證給 A、B

| 檔案 | 放到 |
|---|---|
| `certs/clients/SYS-A.crt` + `.key` | A 機器 `/etc/key-sdk/clients/` |
| `certs/clients/SYS-B.crt` + `.key` | B 機器 `/etc/key-sdk/clients/` |

私鑰權限 `600`。

---

## 第 8 步：在 A、B 上跑

**A 加密：**

```bash
./bin/goclient -base https://key.example.com -certs /etc/key-sdk \
  -system SYS-A -peer SYS-B -data "訂單=A123"
```

**看到這個就算成功：**

```
KEY1.SYS-B:1.ATBZMBMGByq...
```

把它複製到 B。

**B 解密：**

```bash
./bin/goclient -base https://key.example.com -certs /etc/key-sdk \
  -system SYS-B -token "KEY1.SYS-B:1.ATBZMBMGByq..."
```

**看到這個就算成功：**

```
訂單=A123
```

---

## 驗收三條

| # | 做什麼 | 應該看到 |
|---|---|---|
| 1 | A 用 A 的憑證加密 | 成功產出 token |
| 2 | B 用 B 的憑證解密 | 明文一致 |
| 3 | B 改用 A 的憑證去解 | 403 |

第 3 條最重要：**證明身分是憑證決定的，不是參數自報的。**

---

## 跟 PM 對這六條

| PM 的要求 | 在哪裡看到 | 怎麼證明 |
|---|---|---|
| 每系統專屬金鑰 | 後台列表 / `key_versions` 表 | A、B 的 kid 不同 |
| 中央自動產生 | 第 6 步新增後立刻有 kid | 不用手動填金鑰 |
| 各系統自行加解密 | 第 8 步 | 中央只回金鑰，不解密 |
| 5 分鐘緩衝 | 後台點「立即輪替」 | token 變 `:2`，5 分鐘內 `:1` 仍可解 |
| 停用即失效 | 後台點「停用」 | B 取私鑰 403 |
| 後台只有一頁 | `/admin` | 系統登記＋IP＋啟停，沒有別的頁 |

---

## 卡住看這三條

| 症狀 | 原因 | 解法 |
|---|---|---|
| 所有 API 都 401 | Nginx 沒傳身分標頭，或 secret 不一致 | 檢查 `X-Proxy-Secret` 與 `-proxy-secret` 是否相同 |
| 403 且 Nginx 日誌 `verify:NONE` | A 沒帶憑證 | 檢查 `-certs` 路徑與檔名 |
| 後台 403 | `admin_cidr` 沒包含你的 IP | 加白名單，或從 VPN 進 |

---

## 一句話

**編譯 → 起服務 → 配 Nginx → 後台加 A/B → 發憑證 → 跑兩條命令。** 其餘都是維運加固，不在這條主線上。
