# 運維手冊

部署步驟見 [QUICKSTART.md](QUICKSTART.md)；公網配置見 [PUBLIC_DEPLOY.md](PUBLIC_DEPLOY.md)；寶塔見 [BAOTA.md](BAOTA.md)。

## 1. 啟動與停止

```bash
cd /opt/central-key-service
./central.sh start      # 背景啟動，自動讀同目錄的 config.json 與 env
./central.sh status
./central.sh logs
./central.sh restart
./central.sh stop
```

設定檔優先序：`--config` → 程式目錄 `config.json` → `bin/config.json` → `config.local.json` → `/etc/central-key/config.json`。

### systemd（正式環境）

```bash
sudo cp deploy/systemd/central-key.service /etc/systemd/system/
sudo cp deploy/systemd/env.example /etc/central-key/env   # 填入 KEY_KEK
sudo systemctl enable --now central-key
journalctl -u central-key -f
```

> 不要同時用 `central.sh` 與 systemd，會起兩個行程搶同一個埠。

## 2. 儲存後端

| 模式 | 設定 | 適用 |
|---|---|---|
| 記憶體 | `data` 留空 | 臨時演示 |
| JSON 檔 | `data: /var/lib/central-key/state.json` | 單機 |
| MySQL | `dsn: ...`（優先於 data） | 正式、多實例 |

啟動日誌與 `/healthz` 都會顯示目前後端：

```
儲存後端：mysql:tcp(127.0.0.1:3306)/cms_key
{"status":"ok","store":"mysql:..."}
```

多實例時，輪替靠 `service_locks` 租約互斥，寫入前會重新載入。

## 3. 憑證生命週期

- 伺服器憑證：公開 CA，`certbot` 或寶塔自動續期
- 用戶端憑證：自家 CA（`devca` 或企業 CA），CN = 系統代碼
- 續期：到期前 30 天告警；用戶端憑證建議 ≤ 1 年
- 吊銷：CA 端產生 CRL，Nginx 加 `ssl_crl`，同時在後台停用該系統

`devca` 預設**沿用既有 CA**；要重產必須明確加 `-new-ca`，否則先前發出的憑證會全部失效。

## 4. 上線切換

1. 後台登記系統，允許 IP 留空
2. 該系統接入 SDK，先只做解密與輪詢
3. 觀察：輪詢正常、無 403、無未知 kid
4. 切換：把政策從 `disabled` 改成 `required`
5. 驗證：跑一次端到端

順序：**先切接收方，再切發送方**。

## 5. 回滾

| 層級 | 操作 | 影響 |
|---|---|---|
| 單系統 | 政策改 `disabled` | 改走未加密流程，金鑰保留 |
| 停用 | 後台「停用」 | 作廢金鑰，拒絕一切請求 |
| 全面 | 停服務 | 5 分鐘後加密鏈路停擺（不落明文） |

回滾**不是**恢復明文；確認沒有任何系統把「連不上中央」誤判為「不加密」。

## 6. 稽核

- `audit.jsonl`（或 MySQL `audit_log`）：時間、操作者、動作、系統、kid、來源 IP、結果
- **不記錄**私鑰、明文、包裝內容
- 保留 1 年；`GET /api/v1/admin/audit?limit=200` 可匯出
- 建議每日轉存 SIEM

## 7. 監控

`/metrics`（Prometheus 格式）：

| 指標 | 告警條件 |
|---|---|
| `key_sync_total` | 連續 5 分鐘無增長 |
| `key_sync_denied_total` | > 0 且持續 |
| `key_private_key_issued_total` | 單一 kid 短時間大量 |
| `key_private_key_denied_total` | > 0 |
| `key_admin_auth_failure_total` | > 0 |
| `key_systems_enabled` | 下降 |

另建議監控每個系統「最後一次成功同步時間」，超過 120 秒告警。

## 8. 輪替 SOP

**例行**（30 天，自動）：新版預發布 → 生效 → 5 分鐘緩衝 → 舊版退役並銷毀私鑰。

**應急**（疑似外洩）：

1. `POST /api/v1/admin/systems/{code}/rotate` 立即換鑰
2. 確定外洩則 `disable` 再 `enable`（作廢重建）
3. 調閱稽核，確認時間窗
4. 評估時間窗內資料是否需重新加密

## 9. 事故處理

| 事故 | 處置 |
|---|---|
| 中央不可用 | 各系統沿用快取；超過 5 分鐘停止加密並告警，**不得改走明文** |
| 私鑰外洩 | 立即輪替 → 評估影響 → 稽核追溯 |
| 管理權杖外洩 | 更換權杖 → 檢查稽核 → 確認無異常登記 |
| CA 私鑰外洩 | 換 CA、重簽全部憑證（等同全系統重建） |
| 狀態檔損毀 | 由備份還原；無備份需重新登記並換鑰（舊密文將無法解） |

## 10. 版本保留

每小時輪替會持續產生版本。預設策略：

- 退役版本保留 `retention`（720h／30 天）
- 每系統至少保留最近 `retention_keep`（20）個退役版本
- 讀取時不載入退役版本；多實例重載間隔 `refresh_ttl`（1s）

清理每小時自動執行；手動觸發（Java 版）`POST /api/v1/admin/prune`。

## 11. 已知限制

1. **無 HSM**：KEK 在行程記憶體；正式環境建議接 Vault Transit 或 HSM
2. **多實例未壓測**：已支援租約與重新載入，但未做長時間雙實例驗證
3. **SSO 未接**：目前共享權杖；上線前應接 OIDC 並強制 MFA
4. **不加密政策的簽章未在 SDK 驗證**：中央已簽，SDK 端待補
