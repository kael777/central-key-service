# go-key-sdk（參考實作）

cms-key 協定 v1 的 Go 實作，**零第三方依賴**（只用標準庫）。目的是讓 Java／PHP 團隊有一個
可執行的對照物：同樣的輸入必須得到逐位元相同的密文。

## 結構

```
go-key-sdk/
├── keycrypto/            純函式層：無網路、隨機來源可注入
│   ├── keycrypto.go      EncryptTo / EncryptToWith / Decrypt / SPKI 轉換
│   ├── token.go          token 解析與格式驗證
│   ├── errors.go         協定錯誤碼
│   └── keycrypto_test.go 直接跑 ../key-protocol-vectors/v1/vectors.json
├── keyclient/            網路層：/sync 輪詢、快照快取、私鑰取得、降級
└── cmd/vectorcheck/      獨立向量檢查器（CI 可直接執行）
```

## 執行

```bash
go test ./...                                  # 全部測試（含 23 條向量）
go run ./cmd/vectorcheck                       # 手動檢查向量，PASS 23 / FAIL 0
go test -fuzz=FuzzDecrypt -fuzztime=30s ./keycrypto   # 對解密做模糊測試
```

向量路徑可用 `KEY_VECTORS` 覆寫；未設定時會由工作目錄向上尋找 `key-protocol-vectors/v1/vectors.json`。

## 當成函式庫用

```go
c, err := keyclient.New(keyclient.Config{
    BaseURL:    "https://key.internal",
    SystemCode: "SYS-A",
    ClientCert: "/etc/key-sdk/client.crt",
    ClientKey:  "/etc/key-sdk/client.key",
    CAFile:     "/etc/key-sdk/ca.crt",
})
if err != nil {
    return err
}

token, err := c.Encrypt(ctx, "SYS-B", "urlparam", []byte("a=1&b=2"))
pt, err := c.Decrypt(ctx, token, "urlparam") // purpose 必須與加密時一致
```

只想要純函式（例如寫離線工具）：

```go
token, err := keycrypto.EncryptTo(peerSPKI, "SYS-B:3", "urlparam", plaintext)
pt, err := keycrypto.Decrypt(myPriv, token, "urlparam")
```

## 三個關鍵設計

**1. 純函式與網路分離。** 向量測試只碰 `keycrypto`，不需要起中央服務；`keyclient` 用 `httptest`
測，不會依賴外部環境。

**2. 隨機來源可注入。** `EncryptToWith(..., ephScalar, iv)` 傳入固定的臨時私鑰與 IV，
就必須產生與向量**逐字元相同**的 token。這是抓出 HKDF info、AAD 組法、payload 佈局差異的唯一辦法。

**3. 失敗一律 fail-closed。** 快照超過 300 秒且刷新失敗 → `ERR_STALE`，加密端停止而不是轉明文；
認證失敗 → `ERR_AUTH`，不重試、不回傳部分明文。

## 錯誤碼

| 碼 | 情境 |
|---|---|
| `ERR_FORMAT` | 前綴、長度、版本位元組、base64url 非法、超長 |
| `ERR_UNKNOWN_KID` | kid 未登記／已退役／不在授權清單 |
| `ERR_KEY` | 公鑰無效、不在曲線上、非 P-256 |
| `ERR_AUTH` | GCM 認證失敗（密文／tag／AAD 不符） |
| `ERR_STALE` | 快照過期且刷新失敗 |
| `ERR_UNAVAILABLE` | 中央逾時或 5xx |
| `ERR_UNAUTHORIZED` | 403：未登記／停用／IP 不符 |
| `ERR_POLICY_DISABLED` | 中央明確回傳不加密（需驗簽且未過期） |

用 `keycrypto.CodeOf(err)` 取值，不要解析訊息字串。

## 未涵蓋範圍

- **不含中央服務**：`/sync` 與私鑰端點由中央團隊另行實作。
- **TLS 憑證發放**：本套件只負責載入憑證；憑證由內網 CA 簽發。
- **輪替排程**：由中央服務負責，SDK 只被動同步。
- `keyclient` 的 `Encrypt`／`Decrypt` 已用 `httptest` 驗證，但**尚未對接真實中央服務**。

## 給 Java／PHP 實作的對照順序

1. `token.go`：先做解析與格式校驗，跑負向案例（11 條），確認錯誤碼分配一致；
2. `keycrypto.go` 的 `Decrypt`：拿到正向解密全過；
3. `EncryptToWith`：做出「密文重現」全過——這步最難，也最能證明相容；
4. 最後才做網路層。

## 中央服務（可直接起、可測）

```bash
go run ./cmd/devca -out ./certs -systems SYS-A,SYS-B        # 產生 CA + 憑證
go run ./cmd/central -addr 127.0.0.1:8443 \
  -cert certs/server.crt -key certs/server.key -ca certs/ca.crt \
  -admin-token dev-token -data ./data/state.json -audit ./data/audit.jsonl
go run ./cmd/smoke -base https://127.0.0.1:8443             # 端到端驗證
```

| 元件 | 說明 |
|---|---|
| `central/` | 中央服務：mTLS、`/sync`、私鑰下發、輪替與 5 分鐘緩衝、後台單頁、稽核、metrics |
| `cmd/devca` | 產生 CA、伺服器憑證與各系統用戶端憑證（支援 `-count 50`） |
| `cmd/central` | 服務進入點 |
| `cmd/smoke` | 端到端檢查：登記 → A 加密 → B 解密，部署後可直接跑 |
| `../deploy/OPERATIONS.md` | 上線切換、回滾、監控、事故處理 |

後台唯一頁面：`https://<host>:8443/admin`。

## 本地測試（不需要資料庫）

| 情境 | 指令 | 需要什麼 |
|---|---|---|
| 只驗證加解密協定 | `go test ./keycrypto` | 什麼都不用 |
| 驗證中央服務 | `go test ./central` | 什麼都不用（測試內建 CA 與 httptest） |
| 全部 | `go test ./...` | 什麼都不用 |
| 手動跑起來 | `.\scripts\dev.ps1` | Go |
| 部署後自檢 | `go run ./cmd/smoke -base https://127.0.0.1:8443` | 憑證 |

**不需要資料庫。** 狀態存在 `data/state.json`（原子替換寫入），稽核寫 `data/audit.jsonl`；
`-data ""` 則完全在記憶體，重啟即清空，適合測試。

### 設定檔

```bash
cp config.example.json config.local.json     # 修改內容
go run ./cmd/central -config config.local.json
```

優先序：**旗標 > 環境變數 `KEY_KEK` > 設定檔 > 內建預設**。
`kek` 建議留空，改用環境變數，避免主金鑰寫進檔案。

完整欄位說明見 **[CONFIG.md](CONFIG.md)**。至少要改三處：

| 欄位 | 說明 |
|---|---|
| `cert` / `key` / `ca` | 伺服器憑證、私鑰、用戶端 CA |
| `admin_token` | 後台密碼；正式環境換成隨機長字串 |
| `dsn` 或 `data` | MySQL 連線字串，或 JSON 狀態檔 |

走 Nginx 時另外必填 `trusted_proxies` 與 `proxy_secret`；
限制後台來源用 `admin_cidr`；SSO 用 `oidc.*`。

### 後台頁面

瀏覽器開 `https://127.0.0.1:8443/admin`，輸入帳號 `admin`、密碼為管理權杖。
自簽憑證會有警告，選擇繼續即可；若不是用 `cmd/devca` 簽的憑證，需要先信任該 CA。

### 使用 MySQL（多實例／正式環境）

```bash
# 1) 建立資料庫與資料表
go run ./cmd/dbsetup -dsn 'root:密碼@tcp(127.0.0.1:3306)/' -db cms_key

# 2) 設定檔加入 dsn（優先於 data）
#    "dsn": "root:密碼@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC&charset=utf8mb4"

go run ./cmd/central -config config.local.json
```

設定 `dsn` 後，狀態改存 MySQL：

| 資料表 | 用途 |
|---|---|
| `systems` | 系統登記與授權 |
| `key_versions` | 金鑰版本（私鑰以 KEK 包裝） |
| `audit_log` | 稽核紀錄 |
| `service_locks` | 輪替排程的租約（多實例互斥） |

多實例時每次寫入前會重新載入，輪替以 `service_locks` 租約確保只有一個實例執行。

整合測試（需要真實 MySQL）：

```bash
$env:TEST_MYSQL_DSN = "root:密碼@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC"
go test ./central -run MySQL -v
```
