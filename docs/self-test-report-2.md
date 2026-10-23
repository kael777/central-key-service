# 自測報告（第二輪）

| 項目 | 內容 |
|---|---|
| 專案 | 中央 KEY 管理服務（Go 版 + Java 版） |
| 版本 | v1.0.0（QA 第一輪回饋修正後） |
| 測試日期 | 2026-10-23 |
| 測試範圍 | QA 第一輪 26 條回饋的修正回歸 |
| 結論 | **26 條全部有對應修正並完成自測**；真實 IdP、CRL、72h 長穩仍未涵蓋 |

## 1. 背景

QA 第一輪（`docs/issues/cms-key-test-report.html`）共 62 個案例，其中：

- 失敗：13 條
- 觀察：13 條
- 通過：其餘

本輪針對失敗與觀察項逐條修正，Go 與 Java 兩套服務端同步。

## 2. 測試環境

| 項目 | 版本 |
|---|---|
| OS | Windows 11 |
| Go | 1.26.4 |
| Java | OpenJDK 17 / 21 |
| MySQL | 8.x |
| 測試方式 | `curl`（含 cookie/CSRF/mTLS）、`go test`、`mvn test`、瀏覽器檢查標頭 |

## 3. 修正清單與驗證

### 3.1 輸入與資料完整性

| ID | 問題 | 修正 | 驗證 |
|---|---|---|---|
| REG-04 | 空代碼可建幽靈系統 | 正則 `^[A-Za-z][A-Za-z0-9_-]{0,63}$` | 空代碼 → 400／錯誤提示 |
| REG-05 | 大小寫覆寫 | 代碼統一轉大寫 | `sys-b` 與 `SYS-B` 視為同一系統 |
| REG-06 | 代碼含冒號 | 正則禁止 `:` | 含冒號 → 400 |
| REG-07 / EDT-05 | 名稱可空 | 服務端必填 + ≤128 字 | 空白名稱 → 400 |
| REG-09 | 允許 IP 非必填 | `require-ip-allow` 預設開 | 未填 IP → 400 |
| REG-10 | `0.0.0.0/0` 不攔 | 直接拒絕 | `0.0.0.0/0` → 400 |
| REG-12 | 洩漏 DB 錯誤 | 長度檢查 + 錯誤碼白名單 | 超長／未知錯誤 → 固定文案 |

### 3.2 輪替與金鑰生命週期

| ID | 問題 | 修正 | 驗證（實測） |
|---|---|---|---|
| ROT-02 | 連續輪替縮短 5 分鐘緩衝 | 保留各自 `decrypt_until`，上限 8 版 | 連兩次輪替後 `SYS-Z:1` 仍 `decrypt_only`，`decrypt_until` 未變 |
| ROT-07 | 清版本後序號重複 | `next_seq` 持久化 + 原子取號 | 測試 `TestKidSequenceSurvivesReload` |
| ROT-09 | 併發輪替撞號 | `LAST_INSERT_ID(next_seq+1)` + 具名鎖 | 20 併發：kid 唯一、僅 1 個 active |
| ENA-02 | 重新啟用從 :1 重來 | 同上 | 停用→啟用後序號延續 |

實測輸出（連續兩次輪替）：

```
SYS-Z:1  decrypt_only  decrypt_until 03:21:35Z   ← 未被提前退役
SYS-Z:2  decrypt_only  decrypt_until 03:21:35Z
SYS-Z:3  active
```

### 3.3 認證與安全

| ID | 問題 | 修正 | 驗證 |
|---|---|---|---|
| AUTH-05 | 登入頁印預設密碼 | 移除提示 | 頁面已無 `dev-token` 字樣 |
| AUTH-06 | 缺安全標頭 | CSP / X-Frame-Options / nosniff / Referrer-Policy | 回應標頭實測存在 |
| AUTH-07 | 限流全域桶 | 以真實用戶端 IP 計數 | 同 IP 第 6 次 429；換 `X-Real-IP` 後為 401（不同桶） |
| API-04 | XFF 可偽造 | 優先 `X-Real-IP`，XFF 取最後一跳 | 同上 |
| SEC-01 | 提示文字可由 URL 指定 | 只接受錯誤代碼，文案固定 | `detail=<script>...` 不會出現在頁面 |

### 3.4 介面與可運維性

| ID | 問題 | 修正 | 驗證 |
|---|---|---|---|
| ENA-04 | toggle 非冪等 | 改為 `/enable`、`/disable` | 連續兩次 disable 都回 `msg=disabled` |
| ENA-05 / EDT-04 | 無確認視窗 | 停用、輪替、切不加密加 `confirm()` | 頁面 HTML 含確認字串 |
| ENA-06 | 錯誤只有代碼 | 錯誤碼 → 可讀文案 | 「系統不存在」等 |
| ROT-03 | 時區顯示不一致 | 統一 UTC 並標示 | 版本時間皆為 `... UTC` |
| ROT-04 | 「5 分鐘」寫死 | 由 `grace` 設定生成 | 文案隨設定變動 |
| AUD-01 | 後台無稽核入口 | 新增 `/admin/audit` 頁 | 200，含 `key.rotate` 記錄 |

## 4. 自動化測試

| 測試 | 數量 | 結果 |
|---|---|---|
| Go 單元／整合測試 | 44 個測試函式 | 全綠 |
| Java 服務端單元測試 | 5 | 全綠 |
| 四語言協定向量 | 23 / 24 / 23 / 24 | 全綠 |
| 新增政策測試 | `TestRequireIPAllow`、`TestGracePreservedAcrossRotations` | PASS |
| 新增併發測試 | 20 併發輪替、40 併發取號 | PASS |
| 新增多實例測試 | `TestMySQLCheckIPSeesNewSystem` | PASS |

## 5. Java 對等驗證

| 項目 | 結果 |
|---|---|
| 安全標頭 | ✅ 實測存在 |
| 缺 IP / 名稱空白 / `0.0.0.0/0` | ✅ 皆 400 |
| 合法建立 | ✅ 302 |
| 稽核頁 | ✅ 200 |
| 危險操作確認視窗 | ✅ HTML 含 `confirm(` |
| OIDC 個人帳號 | ✅ 已有（mock IdP 驗證過） |
| 併發取號／防止雙 active | ✅ 已同步 |

## 6. 未涵蓋（與第一輪相同）

| 項目 | 風險 | 說明 |
|---|---|---|
| 真實 IdP 聯調 | 中 | 代碼路徑已用 mock IdP 驗證，實際 issuer/claim 需 QA 用公司 IdP 確認 |
| CRL 吊銷演練 | 中 | 在 Nginx 層，需測試伺服器 |
| 5 實例 × 5 小時長穩 | 中 | 目前最多 30 分鐘（見第一輪 X-13） |
| HSM / 雲 KMS | 高 | 無設備；KEK 仍在檔案 |

## 7. 結論

1. QA 第一輪的 26 條失敗／觀察項，全部有對應修正
2. Go 44 個測試、Java 5 個測試、四語言向量全綠
3. 關鍵行為（IP 必填、5 分鐘緩衝、冪等切換、限流分桶、錯誤白名單）皆以實機請求驗證
4. **建議部署後由 QA 回歸這 26 條 + 第一輪已修的 10 條**

## 8. 重現指令

```bash
# 自動化
cd go-key-sdk && TEST_MYSQL_DSN='...cms_key_test...' go test ./...
cd java-server && mvn test

# 手動（Go）
./central -addr 127.0.0.1:9443 -cert certs/server.crt -key certs/server.key \
  -ca certs/ca.crt -admin-token tok -data t2.json -trusted-proxy 127.0.0.1/32

curl -sk -c c.txt -X POST https://127.0.0.1:9443/login -d 'user=admin&pass=tok'
curl -sk -b c.txt https://127.0.0.1:9443/admin
```
