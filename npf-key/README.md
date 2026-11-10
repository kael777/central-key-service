# npf-key-service / npf-key-client

依《NPF 動態金鑰服務計畫書（AWS KMS 版）》實作的 Phase 1：集中保管 HMAC 簽章金鑰，業務服務啟動時拉鑰、之後每小時報到，簽章在業務服務本地完成。

## 模組

| 模組 | 說明 |
|---|---|
| `npf-key-service` | Spring Boot 2.7 服務，JDK 8 位元組碼；兩張表、四支接口、每日輪替 |
| `npf-key-client` | Java 8 工具 jar：拉鑰、記憶體快取、雙簽章 sign/verify、Spring 自動設定 |

## 快速開始（本機）

```bash
# 1. 建庫（MySQL 8）
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS npf_key CHARACTER SET utf8mb4"

# 2. 建置
mvn -DskipTests package

# 3. 啟動（本機 KMS 模式）
java -jar npf-key-service/target/npf-key-service-1.0.0.jar \
  --server.port=8060 \
  --spring.datasource.url='jdbc:mysql://127.0.0.1:3306/npf_key?useSSL=false&serverTimezone=UTC' \
  --spring.datasource.username=root \
  --spring.datasource.password=你的密碼 \
  --npf.kms.mode=local \
  --npf.kms.local-key=dev-only-key
```

啟動時會依 `npf.keys.hmac` 對帳，DB 沒有的鑰自動建立（`CREATE` 審計）。

```bash
curl http://127.0.0.1:8060/health
# {"status":"UP","db":"UP","kms":"local-aes-gcm"}

curl -H 'X-Client-Id: npf-payment' http://127.0.0.1:8060/keys
curl -H 'X-Client-Id: npf-payment' -H 'X-Key-Etag: <上次的 etag>' http://127.0.0.1:8060/keys
# 沒變 → 304，沒有 body
```

## 設定（application.yml）

```yaml
npf:
  refresh-seconds: 3600          # 回給客戶端的建議拉鑰間隔
  kms:
    mode: aws                   # local（開發）或 aws（正式）
    key-arn: arn:aws:kms:...
    local-key: ""               # local 模式的種子，正式不用
  rotate:
    cron: "0 0 10 * * *"        # 每天 10:00
    zone: Asia/Shanghai
    min-interval-hours: 4       # 兩次輪替最小間距
  keys:
    hmac:
      - name: relay.callback
        remark: 支付中轉回調
      - name: relay.daifu.sign
        remark: 代付請求
  clients:
    - id: npf-payment
      ips: [10.0.1.21, 10.0.1.22]
      allowed-keys: [relay.callback, relay.daifu.sign]
```

- **IP 不可重複登記給兩個 client**，啟動時會直接失敗
- 服務前面**不能有 Nginx/LB**：身分只認 TCP 來源 IP，不讀任何轉發 header

## 接口

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/keys` | 批次拉該 client 允許的全部鑰；支援 `X-Key-Etag` → 304 |
| GET | `/keys/{keyName}` | 單把鑰 |
| POST | `/admin/keys/{keyName}/rotate` | 緊急換鑰，僅 127.0.0.1；`dropPrevious=true` 連上一把作廢 |
| POST | `/admin/keys/{keyName}/import` | 匯入對接方鑰，僅 127.0.0.1 |
| GET | `/health` | DB / KMS 狀態 |

回應格式：

```json
{
  "etag": "f9d1b5e89b29528f",
  "refresh": 3600,
  "keys": {
    "relay.callback": {
      "current":  {"id": "019307e0971336ab", "value": "<base64 32 bytes>"},
      "previous": {"id": "a5767264ad2f95f7", "value": "<base64 32 bytes>"}
    }
  }
}
```

錯誤：`403`（IP/服務名/鑰名不符）、`404`（鑰不存在）、`409`（4 小時內重複輪替）、`400`（缺參數）。

## 輪替

- 每天 10:00 對 `npf.keys.hmac` 的每把鑰：目前 CURRENT → PREVIOUS，新的為 CURRENT，舊的 PREVIOUS → RETIRED
- 4 小時內已輪替過 → 跳過並寫 `ROTATE_SKIPPED`
- 兩台實例同時跑：`SELECT ... FOR UPDATE` + `(KEY_NAME, VERSION)` 唯一鍵，只有一台成功
- 手動換鑰：4 小時內不帶 `dropPrevious` 會被拒（409）；帶 `dropPrevious=true` 不受限

## 客戶端

```java
KeyClient client = new KeyClient(new KeyClientConfig()
        .baseUrl("http://npf-key-service:8060")
        .clientId("npf-payment"));
client.start();

KeyClient.SignResult r = client.sign("relay.callback", bodyBytes);
// header: X-Sign-Ts=r.ts, X-Sign=r.sign

boolean ok = client.verify("relay.callback", bodyBytes, ts, sign);
```

- 啟動先拉一次；之後每 1 小時 + 0～300 秒抖動
- 拉失敗沿用記憶體、30 秒後重試
- 超過 20 小時沒更新寫 ERROR
- 簽章格式：`Base64( HMAC-SHA256(ts + "\n" + body, current) ‖ HMAC(..., previous) )`，兩段隨機順序，固定 64 bytes
- 驗簽：時間窗口 300 秒，`MessageDigest.isEqual` 常數時間比較

Spring Boot 自動設定：

```yaml
npf:
  key:
    client:
      base-url: http://npf-key-service:8060
      client-id: npf-payment
      verify-key-name: relay.callback
      verify-paths: ["/doPay/*"]
```

`verify-paths` 有設定時會註冊 `KeyVerifyFilter`，自動驗 `X-Sign-Ts`/`X-Sign` 並提供可重讀 body。

## AWS KMS

正式環境：

- EC2 掛 IAM Role，只允許 `kms:Encrypt`、`kms:Decrypt`、`kms:DescribeKey`（限該 CMK）
- `npf.kms.mode=aws`、`npf.kms.key-arn=...`
- 加密帶 `EncryptionContext={keyName}`，密文調包會解不開
- CMK 開刪除保護與年度自動輪替

## 測試

```bash
mvn test
```

- `KeyClientTest`：簽驗、篡改、時鐘窗口、輪替後舊簽章、304
- `KeyApiTest`：對帳、ETag 304、IP 拒絕、鑰名拒絕、輪替、4 小時間距、本機限制、匯入、health
- `KeyLifecycleTest`：匯入版本演進、排程跳過、併發輪替只有一個成功

## 已知限制

- 沒有 Web 介面；管理只接受本機 curl（SSH 進主機）
- IP 認證要求服務與呼叫端在同一內網、無代理
- SQLite 不支援：需要行鎖與多實例
- 尚未接入正式 AWS（等帳號/區域/CMK）
