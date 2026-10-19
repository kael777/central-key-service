# 中央 KEY 管理服務

給微服務之間傳遞敏感參數用的**金鑰管理服務**：中央產生、輪替、授權金鑰；各系統在自己這一端加密與解密，**中央不接觸業務資料**。

## 它是什麼、不是什麼

```
控制面：A/B ──取公鑰、取私鑰、輪詢版本──▶ 中央（只發鑰匙）
資料面：A ──密文直接送給 B（HTTP / MQ）──▶ B
```

| 是 | 不是 |
|---|---|
| 金鑰的產生、輪替、授權、稽核 | API 网关，不轉發業務流量 |
| 每個系統一組專屬非對稱金鑰 | 資料庫加密 |
| 5 分鐘新舊版解密緩衝 | 身分認證服務（那是 mTLS 的事） |

## 背景：為什麼是星形，而不是網狀

幾十個微服務之間要傳身分證號、訂單號、金額這類參數。明文放 URL 會留在 access log、網關、APM、瀏覽器歷史裡，所以需要「離開 A 之前就加密，到 B 才解開」。

問題是**金鑰怎麼管**。常見兩種做法都不行：

| 做法 | 問題 |
|---|---|
| 兩兩約定共享密鑰 | 50 個系統是 1225 組關係；輪換、吊銷、審計全部失控 |
| 全公司共用一把密鑰 | 洩露一次全軍覆沒，也無法隔離「A 只能給 B」 |

所以改成**星形管鑰匙**：

```
        中央（只發鑰匙、定期換）
       ↗        ↑        ↖
     A  ←─────→ B ←─────→ C     ← 資料仍是點對點（網狀）
```

- **密鑰關係**從 N² 收斂成 N：每個系統只有自己那一對
- 輪替、停用、吊銷、審計都集中在一處
- **資料不經過中央**：A 用 B 的公鑰加密後直接送給 B，中央看不到任何業務內容

代價有兩個，設計上已經補償：

1. **中央是控制面的單點** → 各系統快取金鑰，中央掛掉不影響已啟動的加解密；超過 5 分鐘才停止加密（不落明文）
2. **私鑰下發後收不回** → 靠短週期輪替、停用即換鑰、完整稽核來壓縮風險

換句話說：**把「誰有鑰匙」這件事收斂成星形，把「資料怎麼走」留給原本的網狀架構。**

## 目錄

```
.
├── docs/                    對接與協定文件
├── deploy/                  部署、寶塔、運維、驗收
├── go-key-sdk/              Go 實作（SDK + 中央服務）
│   ├── keycrypto/           純函式層
│   ├── keyclient/           網路層
│   ├── central/             中央服務
│   └── cmd/                 central / devca / dbsetup / smoke / vectorcheck
├── sdks/                    Java / PHP / Node.js SDK
├── key-protocol-vectors/    跨語言測試向量
└── .githooks/               pre-commit（阻擋私鑰與設定誤提交）
```

## 快速開始

```bash
# 1. 編譯（Windows 交叉編譯出 Linux 版本）
go-key-sdk\scripts\build-linux.bat          # 產物在 dist/linux-amd64/

# 2. 起服務（本機測試，不需資料庫）
cd go-key-sdk
./scripts/central.sh start

# 3. 端到端自檢
go run ./cmd/smoke
```

正式部署見 [deploy/QUICKSTART.md](deploy/QUICKSTART.md)。

## 四語言 SDK

| 語言 | 位置 | 依賴 |
|---|---|---|
| Go | `go-key-sdk/` | 標準庫 |
| Java | `sdks/java/` | JDK 17，零依賴 |
| PHP | `sdks/php/` | openssl、hash |
| Node.js | `sdks/node/` | Node 18+，內建模組 |

四套都通過同一份測試向量（6 正 11 負），並能在固定隨機值下產出逐字元相同的密文。
用法見 [docs/sdk.md](docs/sdk.md)。

## 測試

| 範圍 | 指令 |
|---|---|
| 協定（四語言） | `go test ./keycrypto`、`npm test`、`php test/vectors.php`、`run-tests.ps1` |
| 中央服務 | `go test ./central` |
| MySQL 整合 | `TEST_MYSQL_DSN=... go test ./central -run MySQL` |
| 端到端 | `go run ./cmd/smoke` |

## 安全注意

- `config.json`、`certs/`、`data/`（含 KEK）已在 `.gitignore`，**不要提交**
- `KEY_KEK` 是包裝私鑰的主金鑰：資料庫外洩時沒有它解不開私鑰；**換掉它舊私鑰全部失效**
- 用戶端憑證 CN 必須等於系統代碼
- 系統 API 只走 mTLS；後台另有網段限制與登入限流

提交前啟用鉤子：

```bash
git config core.hooksPath .githooks
```

## 文件

| 文件 | 內容 |
|---|---|
| [docs/protocol.md](docs/protocol.md) | 密文格式、金鑰衍生、錯誤碼 |
| [docs/sdk.md](docs/sdk.md) | 四語言對接 |
| [docs/testing.md](docs/testing.md) | 在另一台機器驗證 SDK |
| [deploy/QUICKSTART.md](deploy/QUICKSTART.md) | 30 分鐘跑通 |
| [deploy/PUBLIC_DEPLOY.md](deploy/PUBLIC_DEPLOY.md) | 公網 mTLS 部署 |
| [deploy/BAOTA.md](deploy/BAOTA.md) | 寶塔面板配置 |
| [deploy/OPERATIONS.md](deploy/OPERATIONS.md) | 輪替、回滾、監控、事故 |
| [go-key-sdk/CONFIG.md](go-key-sdk/CONFIG.md) | 設定檔欄位 |


