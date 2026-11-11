# npf-key-service 測試指南

給 RD 自測與 QA 驗收用。範圍是 `npf-key-service` 與 `npf-key-client`，不含 finance／支付中轉的業務改造。

## 1. 環境準備

```bash
# 建庫（獨立 schema，不與 npf 業務庫混用）
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS npf_key CHARACTER SET utf8mb4"

# 建置
cd npf-key
mvn test          # 單元＋整合，應全綠
mvn package       # 產出 npf-key-service-1.0.0.jar、npf-key-client-1.0.0.jar
```

啟動（開發／自測用 local KMS）：

```bash
java -jar npf-key-service/target/npf-key-service-1.0.0.jar \
  --server.port=8060 \
  --spring.datasource.url='jdbc:mysql://127.0.0.1:3306/npf_key?useSSL=false&serverTimezone=UTC' \
  --spring.datasource.username=root \
  --spring.datasource.password='你的密碼' \
  --npf.kms.mode=local \
  --npf.kms.local-key=dev-only
```

啟動時會依 `npf.keys.hmac` 建缺少的鑰。預設範例：

| client | IP | 可拉鑰 |
|---|---|---|
| `npf-payment` | 127.0.0.1 | relay.callback、relay.daifu.sign |
| `payment-relay` | 127.0.0.2 | 同上 |

> 兩個 client 不能共用同一個 IP，否則啟動直接失敗。

## 2. 測試分層

| 層 | 怎麼測 | 驗什麼 |
|---|---|---|
| L1 單元／整合 | `mvn test` | 狀態機、ETag、權限、雙簽章、併發 |
| L2 接口 | curl | 200／304／403／404／409／400 |
| L3 雙實例 | 同一 MySQL 起兩個 port | 行鎖、唯一鍵、只有一台輪替成功 |
| L4 故障 | 停 DB／KMS／重啟 | 可用性與錯誤碼 |
| L5 部署 | HTTPS、Eureka | TLS、註冊 |

## 3. 測試用例

### A. 啟動與對帳

| ID | 操作 | 預期 |
|---|---|---|
| A1 | 空 DB 啟動 | 自動建表、建立 `relay.callback`、`relay.daifu.sign`，審計有 `CREATE` |
| A2 | 再啟動一次 | 不重複建鑰，版本不變 |
| A3 | DB 有一把不在設定名單的 HMAC 鑰 | 啟動 WARN，不刪除、不發放 |
| A4 | 名單有、DB 沒有 | 自動補建 |

### B. 拉鑰與權限

| ID | 操作 | 預期 |
|---|---|---|
| B1 | `GET /keys` + `X-Client-Id: npf-payment`（來源 127.0.0.1） | 200，回 current/previous、etag、refresh |
| B2 | 帶同一 etag 再拉 | 304，無 body |
| B3 | 改一把鑰後帶舊 etag | 200，新 etag |
| B4 | `X-Client-Id` 與來源 IP 不符 | 403，`DENIED` 審計 |
| B5 | 未登記 IP | 403 |
| B6 | 拉不在 allowedKeys 的鑰 | 403 |
| B7 | `GET /keys/{name}` 單把 | 200；不存在的鑰 404 |
| B8 | 偽造 `X-Forwarded-For` / `X-Real-IP` | 不影響身分判定（只認 TCP 來源） |

### C. 輪替與匯入

| ID | 操作 | 預期 |
|---|---|---|
| C1 | `POST /admin/keys/{name}/rotate?reason=test` | 200；舊 CURRENT → PREVIOUS，新 CURRENT |
| C2 | 4 小時內再 rotate（不帶 dropPrevious） | 409 |
| C3 | 帶 `dropPrevious=true` | 200；舊 PREVIOUS → RETIRED |
| C4 | 非 127.0.0.1 呼叫管理接口 | 403 |
| C5 | 缺 `reason` | 400 |
| C6 | `import` 第一次 | 建立 PARTNER CURRENT |
| C7 | `import` 第二次 | 新 CURRENT、舊 CURRENT → PREVIOUS、舊 PREVIOUS → RETIRED |
| C8 | 審計表 | 每次 FETCH／ROTATE／IMPORT／DENIED 都有列 |
| C9 | 排程時間 | 預設每天 10:00（`npf.rotate.cron`） |
| C10 | 4 小時內排程再跑 | 跳過並寫 `ROTATE_SKIPPED` |
| C11 | 停用 `ROTATE_ENABLED=0` 的鑰 | 排程不輪替 |

### D. 雙實例

| ID | 操作 | 預期 |
|---|---|---|
| D1 | 兩個實例同 DB、同時間 rotate 同一把 | 一個 200、一個 409；DB 只有一個 CURRENT |
| D2 | 兩個實例都跑排程 | 只有一台實際輪替，另一台 `ROTATE_SKIPPED` |
| D3 | 兩台都開 Eureka | `/eureka/apps/NPF-KEY-SERVICE` 有兩個 instance（需 Eureka server） |

### E. 客戶端

| ID | 操作 | 預期 |
|---|---|---|
| E1 | `client.sign()` → `client.verify()` | true |
| E2 | 改 body 後 verify | false |
| E3 | ts 超過 300 秒 | false |
| E4 | 輪替後用舊簽章 | 仍 true（previous） |
| E5 | 啟動時服務不可用 | 服務照常起來；sign 拋錯、verify false；30 秒重試直到成功 |
| E6 | 已載入後拉鑰失敗 | 用記憶體舊鑰；10 分鐘後重試 |
| E7 | 20 小時未更新 | ERROR 日誌 |
| E8 | Spring 驗簽 filter：合法簽章 | 放行，controller 可重讀 body |
| E9 | filter：篡改 body 或缺 `X-Sign-Ts` | 403 |

### F. 安全與邊界

| ID | 操作 | 預期 |
|---|---|---|
| F1 | `X-Client-Id` 不帶 | 以 IP 對應的 client 為準 |
| F2 | 管理接口走 proxy／外部 IP | 403 |
| F3 | KMS 解密失敗（local 模式改壞 key） | `/keys` 503；快取 1 小時內仍可發 |
| F4 | 稽核保留 | 180 天前資料會被清（`npf.audit-retention-days`） |
| F5 | HTTPS 啟動 | `--spring.profiles.active=https`，`/keys` 走 TLS |
| F6 | 重啟服務 | 已發出的簽章在 5 分鐘窗口內仍可驗 |

### G. 部署

| ID | 操作 | 預期 |
|---|---|---|
| G1 | Tomcat TLS | 只有 8443，無 HTTP port |
| G2 | 安全群組／防火牆 | 只有名單主機連得到 8060/8443 |
| G3 | Eureka | `EUREKA_ENABLED=true` 後註冊成功 |
| G4 | AWS KMS | `KMS_MODE=aws`、`KMS_KEY_ARN`，EncryptionContext=keyName |

## 4. 快速指令

```bash
BASE=http://127.0.0.1:8060

curl -s $BASE/health
curl -s $BASE/keys -H 'X-Client-Id: npf-payment'
curl -s -o /dev/null -w '%{http_code}\n' $BASE/keys -H 'X-Client-Id: npf-payment' -H 'X-Key-Etag: <etag>'
curl -s -X POST $BASE/admin/keys/relay.callback/rotate -d 'reason=test'
curl -s -X POST $BASE/admin/keys/game.ag.key/import -d 'value=secret' -d 'remark=AG' -d 'reason=partner'
```

```sql
SELECT KEY_NAME, VERSION, STATUS, ROTATED_AT FROM KEY_SECRET ORDER BY KEY_NAME, VERSION;
SELECT ACTION, CLIENT_ID, KEY_NAME, SOURCE_IP, OCCURRED_AT FROM KEY_AUDIT_LOG ORDER BY ID DESC LIMIT 30;
```

## 5. 自測報告要寫什麼

每個用例記：

| 欄位 | 說明 |
|---|---|
| 用例 ID | A1、B2… |
| 操作 | 指令或步驟 |
| 預期 | 上一節的預期 |
| 實際 | 狀態碼／回應摘要 |
| 結果 | 通過／失敗／未執行 |
| 備註 | 環境限制（如 AWS 未接入） |

另附：環境（OS、JDK、MySQL、KMS 模式）、版本（commit）、測試日期、未涵蓋項目與風險。
