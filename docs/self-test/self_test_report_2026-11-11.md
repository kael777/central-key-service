# 自測報告：npf-key-service / npf-key-client（2026-11-11）

| 項目 | 內容 |
|---|---|
| 版本 | `cf77704`（含 Eureka／mock KMS 補測） |
| 日期 | 2026-11-11 |
| 環境 | Windows 11、JDK 17（產出 Java 8 位元組碼）、MySQL 8、local KMS（AES-GCM） |
| 範圍 | `npf-key-service`、`npf-key-client`；不含 finance／支付中轉接入 |
| 結論 | 核心接口、輪替、權限、雙簽章、HTTPS、雙實例通過；AWS KMS、Eureka、真實兩台主機未驗 |

## 1. 自動化測試

```bash
cd npf-key && mvn test
```

| 測試類 | 數量 | 結果 |
|---|---|---|
| `KeyClientTest` | 4 | 通過 |
| `KeyVerifyFilterTest` | 3 | 通過 |
| `KeyApiTest` | 9 | 通過 |
| `KeyLifecycleTest` | 3 | 通過 |
| **合計** | **19** | **0 失敗** |

## 2. 手動／介面測試

### A. 啟動與對帳

| ID | 操作 | 預期 | 實際 | 結果 |
|---|---|---|---|---|
| A1 | 空 DB 啟動 | 自動建表、建兩把鑰、`CREATE` 審計 | 日誌出現 `created key relay.callback`、`relay.daifu.sign` | 通過 |
| A2 | 重啟 | 不重複建鑰 | 版本序號延續，未重建 | 通過 |
| A3 | DB 有、名單沒有的鑰 | WARN、不刪 | — | 未執行 |
| A4 | 名單有、DB 沒有 | 自動補建 | 首次啟動即建立 | 通過 |

### B. 拉鑰與權限

| ID | 操作 | 預期 | 實際 | 結果 |
|---|---|---|---|---|
| B1 | `GET /keys`（npf-payment／127.0.0.1） | 200 | 200，含 current／previous／etag／refresh | 通過 |
| B2 | 同 etag 再拉 | 304 | 304 | 通過 |
| B3 | 輪替後帶舊 etag | 200、新 etag | 200 | 通過 |
| B4 | `X-Client-Id` 與 IP 不符 | 403 | 403 | 通過 |
| B5 | 未登記 IP | 403 | — | 未執行 |
| B6 | 未允許的鑰（`game.ag.key`） | 403 | 403 | 通過 |
| B7 | `GET /keys/{name}` | 200 | 200 | 通過 |
| B8 | 偽造 XFF／X-Real-IP | 不影響 | 程式只讀 `getRemoteAddr()`，`forward-headers-strategy=none` | 設計確認 |

### C. 輪替與匯入

| ID | 操作 | 預期 | 實際 | 結果 |
|---|---|---|---|---|
| C1 | rotate | 200，CURRENT→PREVIOUS | 200，version +1 | 通過 |
| C2 | 4 小時內再 rotate | 409 | 409 | 通過 |
| C3 | `dropPrevious=true` | 200，舊 PREVIOUS → RETIRED | 200 | 通過 |
| C4 | 非本機呼叫管理接口 | 403 | 單元測試通過；實機未測 | 部分 |
| C5 | 缺 `reason` | 400 | 400 | 通過 |
| C6 | 首次 import | 建立 CURRENT | 200，version 1 | 通過 |
| C7 | 再次 import | 新 CURRENT、舊降級 | 200，version 2 | 通過 |
| C8 | 審計 | 每次操作一列 | stdout 出現 `audit action=FETCH …`；DB 未直接查 | 通過（日誌） |
| C9 | 每日 10:00 輪替 | 自動輪替 | 2026-11-11 10:00:00 實際輪替 version 5、6 | 通過 |
| C10 | 4 小時內排程再跑 | 跳過＋`ROTATE_SKIPPED` | 單元測試通過 | 通過（單元） |
| C11 | `ROTATE_ENABLED=0` | 不輪替 | — | 未執行 |

### D. 雙實例

| ID | 操作 | 預期 | 實際 | 結果 |
|---|---|---|---|---|
| D1 | 兩實例同 DB 同時 rotate | 一個 200、一個 409 | 18060=200、18061=409；之後再 rotate 409 | 通過 |
| D2 | 兩實例同時跑排程 | 只有一台輪替 | — | 未執行（同 D1 行鎖機制） |
| D3 | Eureka 註冊 | 兩個 instance | 本機 Eureka 8761，`/eureka/apps/NPF-KEY-SERVICE` 回 18063、18064 兩個 UP | 通過 |

### E. 客戶端

| ID | 操作 | 預期 | 實際 | 結果 |
|---|---|---|---|---|
| E1 | sign → verify | true | 單元測試通過 | 通過 |
| E2 | 篡改 body | false | 通過 | 通過 |
| E3 | ts 超過 300 秒 | false | 通過 | 通過 |
| E4 | 輪替後舊簽章 | true | 通過 | 通過 |
| E5 | 啟動時服務不可用 | 30 秒重試、不擋啟動 | — | 未執行 |
| E6 | 已載入後拉鑰失敗 | 用舊鑰、10 分鐘重試 | — | 未執行 |
| E7 | 20 小時未更新 | ERROR | — | 未執行 |
| E8 | 驗簽 filter 合法 | 放行且 body 可重讀 | 單元測試通過 | 通過 |
| E9 | 篡改／缺時間戳 | 403 | 單元測試通過 | 通過 |

### F. 安全與邊界

| ID | 操作 | 預期 | 實際 | 結果 |
|---|---|---|---|---|
| F1 | 不帶 `X-Client-Id` | 以 IP 對應 client | 200 | 通過 |
| F2 | 管理接口外部 IP | 403 | 單元測試通過 | 通過（單元） |
| F3 | KMS 解密失敗 | 503（快取 1 小時內仍可發） | — | 未執行 |
| F4 | 180 天審計清理 | 逾期資料刪除 | — | 未執行 |
| F5 | HTTPS 啟動 | 只有 TLS port | 18443 https，`/keys` 200 | 通過 |
| F6 | 重啟後舊簽章 | 5 分鐘內可驗 | — | 未執行 |

### G. 部署

| ID | 操作 | 預期 | 實際 | 結果 |
|---|---|---|---|---|
| G1 | HTTPS only | 無 HTTP port | 18443 只開 TLS | 通過 |
| G2 | 安全群組限制 | 只名單主機可連 | — | 未執行（需環境） |
| G3 | Eureka | 註冊成功 | 同上，2 個 instance | 通過 |
| G4 | AWS KMS | `mode=aws` | 本地 mock KMS：health UP、Encrypt/Decrypt/DescribeKey 都帶 EncryptionContext | 部分（SDK 路徑） |

## 3. 未涵蓋與風險

| 項目 | 風險 | 說明 |
|---|---|---|
| 真實 AWS KMS | 中 | 已用 mock 驗 SDK 路徑；IAM／CMK 政策／CloudTrail 未驗 |
| 真實 AWS IAM／CloudTrail | 中 | mock KMS 只驗 SDK 路徑，未驗 IAM 權限與 CloudTrail |
| 真實兩台主機 | 中 | 目前同機兩個 port 共用 MySQL 驗證 |
| KMS 中斷／快取過期 | 中 | 邏輯已寫，未做故障演練 |
| 20 小時未更新告警 | 低 | 需改時鐘或等 20 小時 |
| 180 天審計清理 | 低 | 排程已寫，未等到期 |
| finance／支付中轉接入 | 高 | 不在本專案範圍 |
| 壓測 | 中 | 未做長時間負載 |

## 4. 本輪重跑紀錄（2026-11-11 下午）

### 5.1 自動化

```text
npf-key-client  Tests run: 7,  Failures: 0, Errors: 0
npf-key-service Tests run: 12, Failures: 0, Errors: 0
BUILD SUCCESS
```

### 5.2 接口（兩個實例同一個 MySQL）

```text
18060 health: {"status":"UP","db":"UP","kms":"local-aes-gcm"}
18061 health: {"status":"UP","db":"UP","kms":"local-aes-gcm"}

GET /keys          -> 200
相同 etag 再拉     -> 304

POST /admin/keys/race3.key/import -> 200 {"status":"CURRENT","version":1}

兩實例同時 rotate race3.key：
  18060 -> 200
  18061 -> 409
之後再 rotate（18061）-> 409
```

### 5.3 觀察

- 兩實例共用同一把 CURRENT，行鎖與 4 小時間距都生效
- 第二次請求不會產生第二個 CURRENT
- `race3.key` 是測試資料，報告完成後可刪除

## 5. 重現指令

```bash
# 自動化
cd npf-key && mvn test

# 啟動（local KMS）
java -jar npf-key-service/target/npf-key-service-1.0.0.jar \
  --server.port=8060 \
  --spring.datasource.url='jdbc:mysql://127.0.0.1:3306/npf_key?useSSL=false&serverTimezone=UTC' \
  --spring.datasource.username=root --spring.datasource.password='***' \
  --npf.kms.mode=local --npf.kms.local-key=dev-only

# 接口
curl -s localhost:8060/keys -H 'X-Client-Id: npf-payment'
curl -s -X POST localhost:8060/admin/keys/relay.callback/rotate -d 'reason=test'
```

完整用例見 `npf-key/docs/TEST-GUIDE.md`。
