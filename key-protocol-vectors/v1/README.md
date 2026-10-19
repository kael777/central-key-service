# cms-key 協定測試向量（v1）

跨語言互通性的**唯一權威來源**。Go／Java／PHP 三個 SDK 的 CI 都必須讀同一份 `vectors.json`，
全部通過才算該語言實作完成。

## 檔案

| 檔案 | 用途 |
|---|---|
| `vectors.json` | 測試向量本體（6 組正向、11 組負向） |
| `generate.mjs` | 產生向量並自我驗證（Node 24+，無外部依賴） |
| `verify.mjs` | 獨立驗證器，模擬各語言 SDK 的 CI 檢查 |

## 執行

```bash
node verify.mjs          # 驗證現有向量
node generate.mjs        # 重新產生（會換掉測試金鑰，需同步升版）
```

目前結果：`PASS 23 / FAIL 0`。

## 給 SDK 的用法

1. 讀 `vectors.json`；
2. `positive[*]`：用 `kid` 對應的 `keys[].d_hex` 解開 `token`，比對 `plaintext_b64`（base64 解碼後逐 byte 比對）；
3. `positive[*]` 第二輪：以 `eph_d_hex` 與 `iv_hex` 作為**注入的隨機值**重新加密，輸出必須與 `token` **完全一致**；
4. `negative[*]`：必須回傳 `expect_error` 指定的錯誤碼，**不得**回傳部分明文或 OK。

第 3 點是關鍵：加密本身是隨機的，但把隨機值固定後，三個語言必須輸出位元級相同的密文。
這能一次抓出 HKDF info、AAD 組法、payload 佈局的任何偏差。

## 規則

- `vectors.json` 是規範性文件，**修改需升 protocol 版本**（`v1` → `v2`）。
- 測試金鑰僅供測試，禁止用於任何環境。
- 新增案例一律「正向 + 對應負向」成對加入。
