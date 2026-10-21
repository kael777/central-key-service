# HTTP API 參考（v1）

所有端點都在同一個服務上，預設 `https://<host>:8443`。

兩套實作（Go / Java）的路由與語意一致；差異列在最後。

## 認證

| 類型 | 端點 | 方式 |
|---|---|---|
| 系統 API | `/api/v1/sync`、`/api/v1/self/private-key` | **mTLS**：用戶端憑證 CN = 系統代碼 |
| 管理 API | `/api/v1/admin/*` | 標頭 `X-Admin-Token: <權杖>` |
| 後台頁面 | `/admin`、`/login` | 權杖或 SSO 會話 |

- 系統 API 不接受權杖；身分只從憑證（或受信代理標頭）來。
- 管理 API 的三種權杖對應角色：admin（可新增系統）、operator（可輪替／停用）、viewer（唯讀）。

### 錯誤格式

```json
{"error": "系統未登記：SYS-X"}
```

Java 版額外含 `code` 欄位（`unknown_system` 等）。用戶端判斷請以 HTTP 狀態碼為主。

| 狀態 | 意義 |
|---|---|
| 200 | 成功 |
| 400 | 參數錯誤（缺 kid、格式不符） |
| 401 | 沒有憑證／權杖錯誤 |
| 403 | 系統停用、IP 不符、權限不足 |
| 404 | 系統或版本不存在 |
| 409 | 重複登記、系統停用中、已有待生效版本 |
| 500 | 內部錯誤（含私鑰解封失敗） |

---

## 系統 API

### GET /api/v1/sync

回傳自己的版本清單、對端的現行公鑰，以及即將生效的公鑰。

```bash
curl -s --cert certs/clients/SYS-A.crt --key certs/clients/SYS-A.key \
  https://key.example.com/api/v1/sync
```

```json
{
  "server_time": "2026-10-21T05:00:00Z",
  "self": {
    "system_code": "SYS-A",
    "encryption": {"mode": "required", "policy_id": "p-SYS-A"},
    "decrypt_versions": [
      {"kid": "SYS-A:3", "alg": "ECIES-P256-AES256GCM", "not_before": "2026-10-21T04:00:00Z"}
    ]
  },
  "peers": {
    "SYS-B": {
      "kid": "SYS-B:7",
      "alg": "ECIES-P256-AES256GCM",
      "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
      "not_before": "2026-10-21T04:30:00Z"
    }
  },
  "next": {
    "SYS-B": {
      "kid": "SYS-B:8",
      "alg": "ECIES-P256-AES256GCM",
      "public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
      "not_before": "2026-10-21T05:10:00Z"
    }
  }
}
```

| 欄位 | 說明 |
|---|---|
| `self.decrypt_versions` | 自己可解密的版本（active + 緩衝期內的舊版） |
| `peers` | 對端**現行**公鑰，加密時用這個 |
| `next` | 對端**即將生效**的公鑰；只能快取，**不得提前加密** |
| `server_time` | 伺服器時間（UTC），可用來校正快取年齡 |

### POST /api/v1/self/private-key

取得自己某個版本的私鑰（PKCS#8，base64）。

```bash
curl -s -X POST \
  --cert certs/clients/SYS-A.crt --key certs/clients/SYS-A.key \
  -H "Content-Type: application/json" \
  -d '{"kid":"SYS-A:3"}' \
  https://key.example.com/api/v1/self/private-key
```

```json
{
  "kid": "SYS-A:3",
  "alg": "ECIES-P256-AES256GCM",
  "private_key_b64": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg..."
}
```

- 只能取**自己**的版本；用 A 的憑證要 B 的 kid 會回 403。
- `active`、`pending`（預先取得）與緩衝期內的 `decrypt_only` 可以取；`retired` 回 403／404。
- 回應帶 `Cache-Control: no-store`。

---

## 管理 API

所有請求需帶 `X-Admin-Token`。

### GET /api/v1/admin/systems

```json
[
  {"code":"SYS-A","name":"A 機器","ip_allow":[],"status":"enabled","active_kid":"SYS-A:3"}
]
```

### POST /api/v1/admin/systems

```bash
curl -s -X POST https://key.example.com/api/v1/admin/systems \
  -H "X-Admin-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"SYS-C","name":"C 機器","ip_allow":[],"note":""}'
```

- `code`：英數開頭，僅 `A-Za-z0-9_-`，≤ 64；必須與憑證 CN 相同
- `ip_allow`：CIDR 或精確 IP；留空表示不限制
- 建立後自動產生第一版 active 金鑰

### PUT /api/v1/admin/systems/{code}

更新名稱、允許 IP、備註。僅 Go 版提供。

### POST /api/v1/admin/systems/{code}/rotate

立即輪替：舊版進 `decrypt_only`（緩衝 5 分鐘），新版本立刻 active。

```json
{"kid":"SYS-A:4","state":"active","not_before":"2026-10-21T05:20:00Z"}
```

### POST /api/v1/admin/systems/{code}/schedule

排程輪替：建立 `pending`，`prepublish`（預設 10 分鐘）後自動轉 active。

```json
{"kid":"SYS-A:5","state":"pending","activate_at":"2026-10-21T05:30:00Z"}
```

已有 pending 時回 409。

### GET /api/v1/admin/systems/{code}/versions

```json
[
  {"kid":"SYS-A:4","state":"active","not_before":"2026-10-21T05:20:00Z"},
  {"kid":"SYS-A:3","state":"decrypt_only","not_before":"2026-10-21T04:20:00Z",
   "decrypt_until":"2026-10-21T05:25:00Z"}
]
```

### POST /api/v1/admin/systems/{code}/enable｜disable

- `disable`：立即作廢現行金鑰，該系統所有請求回 403
- `enable`：重新啟用並產生全新金鑰

### GET /api/v1/admin/audit?limit=200

```json
{"entries":[{"ts":"2026-10-21T05:20:00Z","actor":"admin","action":"key.rotate",
  "system":"SYS-A","kid":"SYS-A:4","ip":"10.0.0.5","result":"ok"}]}
```

Java 版回傳陣列本身（沒有 `entries` 包裝）。

### POST /api/v1/admin/prune

手動清理退役版本，回傳 `{"removed": N}`。

---

## 運維端點

| 端點 | 說明 |
|---|---|
| `GET /healthz` | `{"status":"ok","store":"mysql:127.0.0.1:3306/cms_key"}` |
| `GET /metrics` | Prometheus 文字格式 |

主要指標：`key_sync_total`、`key_sync_denied_total`、`key_private_key_issued_total`、
`key_private_key_denied_total`、`key_rotations_total`、`key_systems_enabled`。

---

## 後台與 SSO

| 端點 | 實作 | 說明 |
|---|---|---|
| `GET /admin` | Go / Java | 後台單頁 |
| `GET /login`、`POST /login` | Go | 權杖登入 |
| `GET /auth/login` | Java | 導向 IdP |
| `GET /auth/callback` | Go / Java | OIDC 回呼 |
| `GET|POST /logout` | Go / Java | 登出 |

---

## 行為約定

1. **kid 格式**：`{系統代碼}:{序號}`，例如 `SYS-A:3`
2. **加密用 active**：`peers` 裡的版本
3. **解密接受白名單**：`self.decrypt_versions`，由伺服器控制，用戶端不做時間判斷
4. **緩衝期**：5 分鐘。過了就解不開，屬於預期行為
5. **不加密政策**：`self.encryption.mode` 為 `required` / `disabled`；`disabled` 時不得加密
6. **冪等**：`rotate` 與 `schedule` 非冪等，重試會產生多個版本

## Go / Java 差異

| 項目 | Go | Java |
|---|---|---|
| `PUT /admin/systems/{code}` | ✅ | ❌ |
| `/versions`、`/schedule`、`/prune` | ✅ | ✅ |
| 管理 API 錯誤 body | `{"error"}` | `{"error","code"}` |
| 稽核回應 | `{"entries":[...]}` | `[...]` |
| 後台登入 | `/login` | `/auth/login`（OIDC）＋權杖 |

> 兩邊都通過同一組加解密測試向量；上述差異只影響管理端自動化，不影響系統 API。
