# 中央 KEY 管理服務（Java / Spring Boot）

與 Go 版並行的第二套實作。**協定、資料表結構、狀態機與 Go 版一致**，可與同一批 SDK 互通。

## 目前狀態

| 階段 | 內容 | 狀態 |
|---|---|---|
| Phase 1 | mTLS、`/sync`、私鑰端點、輪替（prepublish／5 分鐘緩衝） | ✅ 完成 |
| Phase 2 | MySQL 儲存（獨立庫 `cms_key_java`）、啟動載入、寫穿 | ✅ 完成 |
| Phase 3 | 後台單頁、稽核、metrics、healthz | ✅ 基本完成（角色僅 admin、無 CSRF） |
| Phase 4 | OIDC SSO、雙版本一致性黑盒測試 | ⏳ 未做 |

### 與 Go 版的功能差異

| 能力 | Go 版 | Java 版 |
|---|---|---|
| 系統 API（sync／私鑰） | ✅ | ✅ |
| 輪替／提前發布／緩衝期 | ✅ | ✅ |
| MySQL | ✅ | ✅（獨立庫） |
| 後台頁面 | ✅ 完整 | ✅ 基本（列表／新增／輪替／停用） |
| 角色（viewer/operator/admin） | ✅ | ❌ 僅 admin |
| CSRF | ✅ | ❌ |
| OIDC SSO | ✅ | ❌ |
| 多實例租約 | ✅ | ❌ 單實例 |

> 上表差異需在 Phase 4 補齊；在那之前 **QA 驗收請以核心流程為主**。

## 啟動

前置：JDK 17+、MySQL、憑證（與 Go 版共用同一組即可）。

```bash
export KEY_KEK=<64 位十六進位>
export DB_PASSWORD=<MySQL 密碼>
export ADMIN_TOKEN=<管理權杖>
export TLS_CERT=file:/opt/central-key-service/certs/server.crt
export TLS_KEY=file:/opt/central-key-service/certs/server.key
export TLS_CA=file:/opt/central-key-service/certs/ca.crt

java -jar target/central-key-service-1.0.0.jar
```

或 Windows：

```powershell
$env:KEY_KEK="..."; $env:DB_PASSWORD="..."; $env:ADMIN_TOKEN="..."
mvn -DskipTests package
java -jar target\central-key-service-1.0.0.jar
```

資料庫 `cms_key_java` 會自動建立（`createDatabaseIfNotExist`）；資料表由程式啟動時建立。

### 可調參數（環境變數）

| 變數 | 預設 | 說明 |
|---|---|---|
| `PORT` | 8443 | 監聽埠 |
| `GRACE_SECONDS` | 300 | 舊版解密緩衝 |
| `PREPUBLISH_SECONDS` | 600 | 提前發布時間 |
| `ROTATION_SECONDS` | 3600 | 自動輪替週期 |
| `TRUSTED_PROXIES` | 空 | 受信代理網段，逗號分隔 |
| `PROXY_SECRET` | 空 | 代理標頭共享密鑰 |

## 驗證（QA 最小清單）

```bash
# 1. 健康檢查
curl -sk https://127.0.0.1:8443/healthz

# 2. 登記兩個系統
curl -sk -X POST https://127.0.0.1:8443/api/v1/admin/systems \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"SYS-A","name":"A"}'
curl -sk -X POST https://127.0.0.1:8443/api/v1/admin/systems \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"SYS-B","name":"B"}'

# 3. 用 Go client 加密（需要憑證）
go run ./examples/goclient -base https://127.0.0.1:8443 -certs ./certs \
  -system SYS-A -peer SYS-B -data "hello"

# 4. 用 SYS-B 解密
go run ./examples/goclient -base https://127.0.0.1:8443 -certs ./certs \
  -system SYS-B -token "KEY1.SYS-B:1...."

# 5. 輪替後舊 token 仍可解（5 分鐘內）
curl -sk -X POST https://127.0.0.1:8443/api/v1/admin/systems/SYS-B/rotate \
  -H "X-Admin-Token: $ADMIN_TOKEN"

# 6. 檢視版本狀態
curl -sk https://127.0.0.1:8443/api/v1/admin/systems/SYS-B/versions \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

實測結果（本機）：

```
sync          → peers.SYS-B:1
encrypt       → KEY1.SYS-B:1....
decrypt       → hello-java
rotate        → SYS-B:2 active，SYS-B:1 decrypt_only
舊 token 解密 → hello-java（緩衝期內）
schedule      → SYS-B:3 pending，5 秒後 active，SYS-B:2 進緩衝
```

## 後台

瀏覽器開 `https://<host>:8443/admin?token=<ADMIN_TOKEN>`。

> 目前只有單一 admin 權杖，沒有角色與 CSRF；**不要直接暴露公網**，用 SSH 隧道或 IP 白名單。

## 已知限制

1. 單實例；多實例需補租約（Phase 4）
2. 無 SSO／角色／CSRF
3. 每次啟動全量載入版本；版本量大時需搭配保留策略
4. 舊版 `retired` 目前不自動清理
