# 中央 KEY 管理服務

各接入系統專屬非對稱金鑰的集中管理服務：中央產生與輪替金鑰，各系統自行加解密，中央不接觸業務資料。

## 目錄結構

```
.
├── 中央 KEY 管理服務.html        PM 需求文件（原始）
├── RD 技術方案補充.html          RD 技術方案（演算法／API／部署／風險）
├── PM 決策確認單.html            5 項待 PM 簽核的決策
├── SDK 介面定義與測試向量.html    協定規格、錯誤碼、驗收門檻
├── SDK 四語言接入指南.html        四語言 SDK 的接入說明與踩坑
│
├── go-key-sdk/                  Go 實作
│   ├── keycrypto/               純函式層（加解密、token 解析）
│   ├── keyclient/               網路層（輪詢、快取、降級）
│   ├── central/                 中央服務（mTLS、輪替、後台、稽核、MySQL）
│   ├── cmd/
│   │   ├── central/             服務進入點
│   │   ├── devca/               產生 CA 與各系統憑證
│   │   ├── dbsetup/             建立 MySQL 資料庫與資料表
│   │   ├── smoke/               端到端自檢
│   │   └── vectorcheck/         測試向量檢查器
│   ├── scripts/dev.ps1          一鍵啟動本機環境
│   ├── RUNBOOK.md               上線切換、回滾、監控、事故處理
│   └── README.md
│
├── sdks/
│   ├── java/                    Java SDK（JDK 17，零依賴）
│   ├── php/                     PHP SDK + cron CLI
│   └── node/                    Node.js SDK
│
└── key-protocol-vectors/v1/     測試向量（6 正 11 負）與驗證器
```

## 快速開始

```powershell
# 1) 產生憑證並啟動（不需要資料庫）
cd go-key-sdk
.\scripts\dev.ps1

# 2) 另一個視窗：端到端自檢
go run ./cmd/smoke
```

瀏覽器開 `https://127.0.0.1:8443/admin`，帳號 `admin`，密碼為管理權杖（預設 `dev-token`）。

用 MySQL（多實例／正式環境）：

```powershell
go run ./cmd/dbsetup -dsn "root:密碼@tcp(127.0.0.1:3306)/" -db cms_key
go run ./cmd/central -config config.local.json   # 設定檔加 "dsn"
```

## 測試

| 範圍 | 指令 | 需要什麼 |
|---|---|---|
| 協定（四語言） | `go test ./keycrypto`、`npm test`、`php test/vectors.php`、`java -cp out VectorTest` | 只要 runtime |
| 中央服務 | `go test ./central` | 只要 Go |
| MySQL 整合 | `TEST_MYSQL_DSN=... go test ./central -run MySQL` | 真實 MySQL |
| 端到端 | `go run ./cmd/smoke` | 已啟動的服務 |

## 安全注意

- `go-key-sdk/certs/`、`go-key-sdk/data/` 內含**私鑰與 KEK**，已在 `.gitignore` 排除，請勿提交。
- `config.local.json`（含 DSN）同樣不進版控，範本見 `go-key-sdk/config.example.json`。
- 主金鑰建議改用環境變數 `KEY_KEK`，不要寫進設定檔。
- 更換 KEK 會導致既有私鑰無法解開，換之前先確認或重建資料。

## 文件索引

| 文件 | 給誰看 |
|---|---|
| `中央 KEY 管理服務.html` | PM 原始需求 |
| `RD 技術方案補充.html` | 架構、演算法、部署、風險 |
| `PM 決策確認單.html` | 需 PM 拍板的 5 項 |
| `SDK 介面定義與測試向量.html` | 協定規格與向量 |
| `SDK 四語言接入指南.html` | 各系統接入人員 |
| `go-key-sdk/RUNBOOK.md` | 運維與值班 |

## Git 設定（每個 clone 執行一次）

```bash
git config core.hooksPath .githooks
```

`pre-commit` 鉤子會阻擋：`certs/`、`data/`、`*.key/.pem/.p12/.pfx`、`.env`、`*.local.json`，
以及內容含 `BEGIN PRIVATE KEY` 的檔案。確有必要時用 `git commit --no-verify` 略過。

## 分支約定（建議）

| 分支 | 用途 |
|---|---|
| `main` | 可部署版本 |
| `feat/*` | 功能（例如 `feat/mysql-store`） |
| `fix/*` | 修正 |

提交訊息建議用 Conventional Commits：`feat:`、`fix:`、`docs:`、`chore:`。