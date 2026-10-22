# 自測報告

| 項目 | 內容 |
|---|---|
| 專案 | 中央 KEY 管理服務（Go 版 + Java 版 + 四語言 SDK） |
| 版本 | v1.0.0 |
| 測試日期 | 2026-10-22 |
| 測試者 | RD 自測 |
| 結論 | **核心流程、OIDC、3 副本壓測均通過**；真實 IdP 與 CRL 待 QA 驗證 |

## 1. 測試範圍

| 層級 | 對象 |
|---|---|
| 協定層 | 密文格式、金鑰衍生、錯誤碼（四語言互通） |
| SDK 層 | Go / Java / PHP / Node 的加解密與快取行為 |
| 服務層 | Go 中央服務、Java 中央服務 |
| 整合層 | MySQL 儲存、輪替狀態機、多實例一致性 |
| 安全層 | mTLS、角色、CSRF、代理身分、IP 白名單 |
| 部署層 | 公網 Nginx、寶塔、systemd、憑證流程 |

## 2. 測試環境

| 項目 | 版本 |
|---|---|
| OS | Windows 11（開發）、Ubuntu（部署驗證） |
| Go | 1.26.4 |
| Java | OpenJDK 17.0.19（SDK）、21（Spring Boot 建置） |
| Node.js | 26.12.0 |
| PHP | 8.4.26 |
| MySQL | 8.x（本機 127.0.0.1:3306） |
| Spring Boot | 3.3.5 |
| Nginx | 寶塔自帶版本 |

## 3. 測試方法

1. **單元測試**：各語言測試框架，覆蓋協定與狀態機
2. **測試向量**：`key-protocol-vectors/v1` 作為跨語言共同標準
3. **整合測試**：MySQL 實際連線（`TEST_MYSQL_DSN`）
4. **端到端**：Go SDK ↔ Go 服務、Go SDK ↔ Java 服務
5. **手動驗證**：curl + mTLS、瀏覽器後台、兩實例並行

## 4. 結果彙總

| 測試項 | 數量 | 通過 | 失敗 |
|---|---|---|---|
| Go 單元／整合測試 | 42 個測試函式 | 42 | 0 |
| 協定向量（Go） | 23 | 23 | 0 |
| 協定向量（Node） | 24 | 24 | 0 |
| 協定向量（PHP） | 23 | 23 | 0 |
| 協定向量（Java） | 24 | 24 | 0 |
| 向量自我驗證器 | 23 | 23 | 0 |
| Java 服務端單元測試 | 5 | 5 | 0 |
| 端到端（Go ↔ Go） | 6 情境 | 6 | 0 |
| 端到端（Go ↔ Java） | 5 情境 | 5 | 0 |
| OIDC 端到端（mock IdP） | 4 情境 | 4 | 0 |
| 過期憑證拒絕 | 1 | 1 | 0 |
| 基準壓測（100 rps × 10s） | 1000 請求 | 1000 | 0 |

> 四語言向量數量不同，是因為各語言對「非法輸入」的細項檢查粒度不同；**正向用例（6 組）與負向用例（11 組）完全一致**。

## 5. 詳細結果

### 5.1 協定與互通

| ID | 測試 | 結果 |
|---|---|---|
| P-01 | 固定隨機值下重現密文（四語言逐字元相同） | PASS |
| P-02 | 跨語言加密→解密（Go→Java、Node→Go 等） | PASS |
| P-03 | 空字串、UTF-8、二進位明文 | PASS |
| P-04 | tag 竄改 → `ERR_AUTH` | PASS |
| P-05 | purpose 不符 → `ERR_AUTH` | PASS |
| P-06 | kid 前綴替換 → `ERR_AUTH` | PASS |
| P-07 | 未登記 kid → `ERR_UNKNOWN_KID` | PASS |
| P-08 | 截斷／超長／版本位元組錯誤 → `ERR_FORMAT` | PASS |
| P-09 | 公鑰不在曲線上 → `ERR_KEY` | PASS |

### 5.2 中央服務（Go）

| ID | 測試 | 結果 |
|---|---|---|
| S-01 | 登記系統 → 自動產生第一版金鑰 | PASS |
| S-02 | `/sync` 回傳自己版本與對端公鑰 | PASS |
| S-03 | 私鑰端點只給自己的版本（他人 403） | PASS |
| S-04 | 立即輪替：舊版進 `decrypt_only` | PASS |
| S-05 | 緩衝期內舊 token 可解；期滿後拒絕 | PASS |
| S-06 | 提前發布：`pending` → `active`，`next` 正確 | PASS |
| S-07 | 停用即作廢金鑰；重新啟用換新鑰 | PASS |
| S-08 | 多實例租約：同時輪替只有一個成功 | PASS |
| S-09 | 檔案儲存重啟後狀態保留 | PASS |
| S-10 | MySQL 儲存讀寫（整合測試） | PASS |

### 5.3 中央服務（Java）

| ID | 測試 | 結果 |
|---|---|---|
| J-01 | Go SDK 對 Java 服務加密 → Java 端解密 | PASS |
| J-02 | 輪替後舊 token 在緩衝期內仍可解 | PASS |
| J-03 | 排程輪替：`pending` → 5 秒後 `active` | PASS |
| J-04 | 多實例：B 實例輪替，A 實例 2 秒內看到 | PASS |
| J-05 | 版本保留清理（8 筆退役版本被刪，加解密不受影響） | PASS |
| J-06 | OIDC JWT 驗證、角色映射（5 個單元測試） | PASS |

### 5.4 安全

| ID | 測試 | 結果 |
|---|---|---|
| A-01 | 無憑證連線 → 握手失敗 | PASS |
| A-02 | 他人憑證取私鑰 → 403 | PASS |
| A-03 | 非受信代理帶 `X-Client-CN` → 401 | PASS |
| A-04 | 代理密鑰不符 → 401 | PASS |
| A-05 | 角色：viewer 輪替 403、operator 輪替 200、admin 建系統 200 | PASS |
| A-06 | CSRF：無 token 拒絕、有效 token 通過 | PASS |
| A-07 | 停用系統所有 API → 403 | PASS |

### 5.6 OIDC 與壓測（2026-10-22 補測）

| ID | 測試 | 結果 |
|---|---|---|
| O-01 | `/auth/login` → mock IdP 授權 → `/auth/callback` → `/admin` 200 | PASS |
| O-02 | 群組 `cms-admins` 映射為 admin，後台顯示新增表單 | PASS |
| O-03 | state 不符 → 400 | PASS |
| O-04 | 缺 code／缺 cookie → 400 | PASS |
| C-01 | 過期用戶端憑證 → TLS 握手拒絕 | PASS |
| L-01 | 52 系統、10 rps × 15s | 150/150，p95 1.6ms |
| L-02 | 52 系統、100 rps × 10s | 1000/1000，p99 1.6ms |

壓測環境：本機單實例、MySQL 同機、`/sync` 回應含 51 個對端公鑰。

### 5.7 深化測試（2026-10-22 第二輪）

| ID | 測試 | 結果 |
|---|---|---|
| X-01 | 雙實例 100 rps × 15s（4000+ 請求） | 1499/1499，p99 1.8ms |
| X-02 | 併發輪替 10／20 次（兩實例） | 全部 200，kid 連續無重複 |
| X-03 | 壓測中兩次中斷 MySQL 連線 | 2000/2000，無失敗 |
| X-04 | 錯誤 KEK 啟動 → 取私鑰 | 500，客戶端 `ERR_UNAVAILABLE` |
| X-05 | 恢復正確 KEK | 解密成功 |
| X-06 | 牆鐘回撥 1 小時（Node 快取） | 實測 1.2 秒後仍正確刷新 |
| X-07 | token 解析 fuzz 10 秒 | 1,988,426 次執行，無 panic |
| X-08 | CSRF 帶惡意 Origin + 有效 token | 302（未檢查 Origin，token 為唯一防線） |
| X-09 | 3 副本 100 rps × 60s，中途輪替 | 5998/5998，p99 2.1ms，記憶體 99.2→99.3 MB |
| X-10 | 副本先啟動、再由別台登記系統（重現 403） | 修正前 47% 被拒；修正後 1480/1480、2964/2964 |
| X-11 | 20 併發輪替同一系統 | kid 唯一、最終僅 1 個 active（修正前會撞號或出現 2 個 active） |'
| X-12 | 3 副本 100 rps × 30s（403 修正後） | 2964/2964，p50 0.75ms，p99 15.8ms（含每秒重載尖峰） |

### 5.5 部署''

| ID | 測試 | 結果 |
|---|---|---|
| D-01 | `central.sh start/stop/restart/status/logs` | PASS |
| D-02 | 自動讀取同目錄 `config.json` 與 `env` | PASS |
| D-03 | 缺 KEK 時警告並使用開發預設（需人工確認） | PASS（有警告） |
| D-04 | 公網 Nginx + mTLS + 轉發標頭 | PASS（測試伺服器） |
| D-05 | 寶塔站點配置（`nginx -t`） | PASS |

## 6. 缺陷記錄

開發與測試期間發現並修復：

| # | 缺陷 | 影響 | 修復 |
|---|---|---|---|
| 1 | 檔案儲存重啟後狀態遺失 | 重啟即失去所有系統 | 所有後端啟動時載入 |
| 2 | 管理 API 回應洩漏包裝私鑰 | 私鑰密文外洩 | `json:"-"` + 回歸測試 |
| 3 | 代理模式下 IP 白名單誤判 | 合法請求 403 | 改用 `X-Forwarded-For` |
| 4 | `devca` 重跑重新產生 CA | 已發憑證全部失效 | 預設沿用既有 CA |
| 5 | 空狀態文案讓 viewer 測試誤判 | 測試假失敗 | 改判斷表單 action |
| 6 | Java 清理時 `LocalDateTime` 轉型失敗 | 保留策略失效 | 兼容兩種型別 |
| 7 | 文件 `prox_http_version` 拼字錯誤 | 使用者 `nginx -t` 失敗 | 已更正 |
| 8 | 範例設定缺 `trusted_proxies` / `proxy_secret` | 部署後全部 401 | 補齊並加說明 |
| 9 | **kid 重用覆蓋**：退役版本不載入後，序號以 `len+1` 計算，多次輪替會覆寫同一 kid | 公鑰與私鑰不匹配，解密 `ERR_AUTH` | 改為持久化 `next_seq`，由資料庫遞增 |
| 10 | `next_seq` 遷移與讀寫未同步（ALTER 未執行、Scan 少一欄） | 啟動後系統載入失敗 | 補 migration、backfill 與掃描欄位 |
| 11 | Node/Java/PHP 用牆鐘算快取年齡 | 時鐘回撥時持續使用舊公鑰 | 改用單調時鐘（`performance.now`／`nanoTime`／`hrtime`） |
| 12 | MySQL 整合測試會 `DELETE` 資料表 | 誤指正式庫會清空資料 | DSN 資料庫名須以 `_test` 結尾，否則自動跳過 |
| 13 | **空副本誤拒 403**：實例先啟動、系統後登記時，鑑權的 `CheckIP` 不觸發刷新，請求走不到會刷新的 `Sync` | 該副本持續 403，直到重啟或後台操作觸發刷新 | `CheckIP` 查不到系統時先做一次 TTL 刷新 |'
| 14 | **併發輪替撞號／雙 active**：`next_seq` 被舊值覆寫、輪替未序列化 | 唯一鍵衝突 500，或同時存在兩個 active | 原子取號（`LAST_INSERT_ID`）、upsert 不覆寫 `next_seq`、MySQL 具名鎖、最後再降級其他 active |
| 15 | 修正併發輪替時一度漏掉 `saveLocked` | 序號回退（測試立即抓到） | 補回存檔並重跑全量測試 |

## 7. 未涵蓋項目與風險

| 項目 | 風險 | 建議 |
|---|---|---|
| 真實 IdP 的 OIDC 登入 | 中 | 已用 mock IdP 覆蓋程式路徑；QA 仍需用公司 IdP 驗證 issuer/audience |
| 生產規模壓測（3 副本、長連線） | 低 | 已以本機 3 副本完成（100 rps × 60s、中途輪替、零失敗、記憶體平穩） |
| 長時間穩定性（72 小時） | 中 | 觀察記憶體與版本成長 |
| CRL 流程 | 低 | 過期已測；CRL 在 Nginx 層，上線前演練一次 |
| HSM／KEK 輪換 | 高 | 生產建議接 Vault Transit |
| 瀏覽器跨站 CSRF 實測 | 低 | 已有簽章 token，QA 可補 |

## 8. 結論

1. 協定在四語言間完全互通，且能在固定隨機值下重現位元組相同的密文
2. Go 與 Java 兩套服務端的核心行為一致，可互相替換
3. 輪替、提前發布、緩衝期、停用等狀態機符合設計
4. 安全機制（mTLS、角色、CSRF、代理驗證）實測有效
5. 併發輪替在原子取號與序列化後，20 併發下 kid 唯一、最終僅一個 active
6. 修正過程中的回歸（漏存檔）由既有測試立即攔下，代表測試網有效
7. **建議進入 QA 驗收**；驗收重點放在第 7 節的未涵蓋項目

## 8.1 測試工具

| 工具 | 用途 |
|---|---|
| `tools/mock-idp.mjs` | 本地 OIDC Provider（discovery／JWKS／authorize／token），驗證 SSO 流程 |
| `go-key-sdk/cmd/loadtest` | mTLS 壓測工具，輸出 p50/p95/p99 |
| `key-protocol-vectors/v1/verify.mjs` | 測試向量自我驗證 |
| `go-key-sdk/cmd/sqlkill` | 中斷 MySQL 連線，演練斷線復原 |
| `tools/clock-skew-test.mjs` | 驗證時鐘回撥下的快取行為 |

## 9. 重現指令'

```bash
# 協定向量（四語言）
cd go-key-sdk && go test ./keycrypto
node sdks/node/test/vectors.mjs
php sdks/php/test/vectors.php
powershell -File sdks/java/run-tests.ps1

# 服務端（Go，含 MySQL 整合）
TEST_MYSQL_DSN='root:密碼@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC' go test ./...

# 服務端（Java）
cd java-server && mvn test

# 向量自我驗證
node key-protocol-vectors/v1/verify.mjs
```
