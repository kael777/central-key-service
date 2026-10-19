# 運維手冊（Runbook）

中央 KEY 管理服務的部署、上線切換、回滾與事故處理。**本手冊對應 `cmd/central` 的實作**。

## 1. 啟動

**最簡（本機／測試機）**：

```powershell
.\scripts\dev.ps1            # 自動產生憑證與 KEK，啟動服務
```

或用設定檔（推薦，見 `config.example.json`）：

```bash
go run ./cmd/central -config config.local.json
```

設定優先序：**旗標 > 環境變數 `KEY_KEK` > 設定檔 > 內建預設**。

手動指定全部參數：

```bash
# 1) 產生 CA 與憑證（開發／內網測試）
go run ./cmd/devca -out ./certs -systems SYS-A,SYS-B
#    50 個系統一次產生：
go run ./cmd/devca -out ./certs -count 50 -prefix SYS-

# 2) 啟動服務
go run ./cmd/central \
  -addr :8443 \
  -cert certs/server.crt -key certs/server.key -ca certs/ca.crt \
  -admin-token "$ADMIN_TOKEN" \
  -kek "$(openssl rand -hex 32)" \
  -data /var/lib/key-service/state.json \
  -audit /var/log/key-service/audit.jsonl
```

| 參數 | 說明 | 正式環境 |
|---|---|---|
| `-kek` | 包裝私鑰的主金鑰（64 位十六進位） | **必填**，不可與狀態檔同機存放 |
| `-data` | 狀態檔（原子替換寫入） | 單機測試用 |
| `-audit` | 稽核 JSONL | 必填，保留 1 年 |
| `-grace` | 新舊版並存時間 | 維持 5 分鐘，勿改 |
| `-rotation` | 自動輪替週期 | 30 天（決策 D1） |
| `-admin-token` | 後台權杖 | **測試期用**；上線前改接 SSO |

## 1.1 儲存後端

| 模式 | 設定 | 適用 |
|---|---|---|
| 記憶體 | `-data ""` | 單元測試、臨時演示 |
| JSON 檔 | `-data data/state.json` | 單機試點 |
| MySQL | `-dsn "user:pass@tcp(host:3306)/cms_key?parseTime=true&loc=UTC"` | 正式、多實例 |

建立資料表：`go run ./cmd/dbsetup -dsn "root:pass@tcp(127.0.0.1:3306)/" -db cms_key`。
多實例時，輪替排程透過 `service_locks` 租約互斥，寫入前會重新載入，避免互相覆蓋。


## 1.2 身分驗證與權限

後台支援兩種登入模式，由設定決定：

| 模式 | 設定 | 適用 |
|---|---|---|
| 共用權杖 | 不設 `oidc.issuer` | 內網測試、QA |
| OIDC SSO | 設 `oidc.issuer` 等欄位 | 正式環境 |

### 權限角色

| 角色 | 可做 |
|---|---|
| `viewer` | 查看系統列表 |
| `operator` | 啟用／停用／立即輪替 |
| `admin` | 新增／修改系統 |

OIDC 模式由 `group_roles` 對應群組到角色，未對應時使用 `default_role`（預設 `viewer`）：

```json
"oidc": {
  "issuer": "https://sso.example.com",
  "client_id": "cms-key",
  "client_secret": "...",
  "redirect_url": "https://key.internal/auth/callback",
  "group_roles": { "cms-admins": "admin", "cms-ops": "operator" },
  "default_role": "viewer"
}
```

### 三個密鑰的分工

| 設定 | 用途 |
|---|---|
| `admin_token` | 網頁登入密碼（僅權杖模式） |
| `api_token` | 管理 API 的 `X-Admin-Token`；與網頁密碼分離 |
| `session_secret` | 簽章 cookie；洩漏時可單獨輪換而不影響 API |

三者留空時會回退到 `admin_token`，正式環境建議分別設定。

### 其他保護

- **CSRF**：所有後台表單需帶簽章 token，缺漏回 403
- **登入限流**：同 IP 5 分鐘內失敗 5 次即封鎖
- **後台網段**：`admin_cidr` 限制 `/admin` 與 `/api/v1/admin/*` 來源
- **審計到人**：`audit_log.actor` 記錄實際使用者（SSO 帳號）
## 2. 憑證生命週期

- 每個接入系統一張用戶端憑證，**CN = 系統代碼**，伺服器以此識別身分。
- 憑證由內網 CA 簽發；`cmd/devca` 只供測試，正式環境請用既有 CA 流程。
- 續期／吊銷走 CA 既有流程；吊銷後該系統立即無法取得任何 KEY。
- 憑證遺失＝該系統可被冒充，**處置方式：吊銷憑證 + 立即輪替該系統金鑰**。

## 3. 上線切換（Cutover）

新系統從明文改為加密，**不要一次切**：

1. **登記**：建立系統（`POST /api/v1/admin/systems`），此時中央已產生金鑰，但政策模式設為
   `disabled`（`PUT /api/v1/admin/systems/{code}` 帶 `{"mode":"disabled"}`）。
2. **接入 SDK**：該系統先只實作「解密」與「輪詢」，能處理舊格式。
3. **觀察**：確認輪詢正常、無 403、無未知 kid。
4. **切換**：`{"mode":"required"}` → 該系統開始加密。
5. **驗證**：跑 `go run ./cmd/smoke`（或等價的健康檢查），確認端到端可解。

順序建議：**先切接收方（B），再切發送方（A）**。反過來會出現 A 已加密、B 還不認得的情況。

## 4. 回滾

**回滾不是「恢復明文」，是把政策改成明確的 `disabled`。** 三種層級：

| 層級 | 操作 | 影響 |
|---|---|---|
| 單系統回滾 | `PUT .../{code}` `{"mode":"disabled"}` | 該系統改走未加密流程；金鑰保留 |
| 停止某系統 | `POST .../{code}/disable` | 作廢金鑰、拒絕一切請求（決策 D2） |
| 全面停用 | 停掉服務 | 5 分鐘後所有加密鏈路停擺（不落明文） |

回滾後務必確認：**沒有任何系統把「連不上中央」誤判為 `disabled`**。這是本設計最關鍵的一條不變量。

## 5. 稽核與保留

- 寫入 `audit.jsonl`，欄位：時間、操作者、動作、系統、kid、來源 IP、結果。
- **永不記錄**私鑰、明文、金鑰包裝內容。
- 保留 1 年；查詢走 `GET /api/v1/admin/audit?limit=200` 或直接分析 JSONL。
- 建議每日轉存至 SIEM，本機保留 30 天。

## 6. 監控與告警

`GET /metrics`（Prometheus 文字格式）：

| 指標 | 告警條件 | 意義 |
|---|---|---|
| `key_sync_total` | 連續 5 分鐘無增長 | 所有系統都停止輪詢 |
| `key_sync_denied_total` | > 0 且持續 | 有系統被拒（未登記／停用／IP 不符） |
| `key_private_key_issued_total` | 單一 kid 短時間大量 | 疑似異常取用或發布風暴 |
| `key_private_key_denied_total` | > 0 | 有人嘗試取用無權限的版本 |
| `key_admin_auth_failure_total` | > 0 | 後台權杖被猜測 |
| `key_systems_enabled` | 下降 | 系統被停用 |

另建議對每個系統監控「最後一次成功同步時間」，超過 2 個週期（120 秒）即告警。

## 7. 金鑰輪替 SOP

**例行**（每 30 天，自動）：
1. 新版本 `pending` 提前 10 分鐘預發布（公鑰先下發）；
2. 到點轉 `active`，舊版 `decrypt_only`；
3. 5 分鐘後舊版 `retired`，包裝私鑰銷毀。

**應急**（疑似外洩）：
1. `POST /api/v1/admin/systems/{code}/rotate` 立即換鑰；
2. 若確定外洩，改為 `disable` 再 `enable`（等於作廢並重建）；
3. 調閱稽核，確認外洩時間窗；
4. 評估該時間窗內的資料是否需要重新加密。

## 8. 事故處理

| 事故 | 處置 |
|---|---|
| 中央不可用 | 各系統沿用快取；超過 5 分鐘停止加密並告警。**不得改走明文** |
| 私鑰外洩 | 立即輪替 → 評估影響 → 稽核追溯 |
| 管理權杖外洩 | 更換權杖 → 檢查稽核 → 確認無異常登記 |
| CA 私鑰外洩 | 換 CA、重簽全部憑證（等同全系統重建） |
| 狀態檔損毀 | 由備份還原；若無備份，需重新登記並換鑰（舊密文將無法解） |

## 9. 已知限制（上線前必須補）

1. **多實例**：已支援 MySQL（`dsn` 設定 + `service_locks` 租約），但尚未做長時間雙實例壓力驗證。
2. **無 HSM**：KEK 目前在行程記憶體；正式環境應接 Vault Transit 或 HSM。
3. **管理員認證為共用權杖**：上線前接 OIDC/SSO 並強制 MFA。
4. **不加密政策的簽章**：已預留 `policy_signature` 欄位並以 ECDSA 簽署，但 SDK 端尚未驗簽。
5. **多實例**：輪替排程需 PostgreSQL advisory lock，目前為單實例假設。


