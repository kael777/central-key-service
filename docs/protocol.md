# 協定規格（cms-key v1）

本文件是 Go / Java / PHP / Node 四套 SDK 的共同依據。改動任一細節都屬於破壞性變更，必須升版本。

## 1. 密文格式

```
KEY1.{kid}.{base64url(payload)}
```

`payload` 的位元組佈局：

| 欄位 | 長度 | 說明 |
|---|---|---|
| 版本 | 1 byte | 固定 `0x01` |
| 臨時公鑰 | 91 bytes | P-256 SubjectPublicKeyInfo (DER) |
| IV | 12 bytes | AES-GCM nonce |
| 密文 | N bytes | 明文長度 |
| Tag | 16 bytes | GCM 認證標籤 |

範例：

```
KEY1.SYS-B:3.ATBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IAB...
```

## 2. 金鑰衍生

| 項目 | 值 |
|---|---|
| 曲線 | P-256（secp256r1） |
| ECDH | 臨時私鑰 × 對方公鑰，得到 32 bytes 共享秘密 |
| KDF | HKDF-SHA256 |
| salt | 空（等價 32 bytes 零） |
| info | `cms-key-v1\|{kid}\|{purpose}` |
| 輸出 | 32 bytes AES key |
| 加密 | AES-256-GCM |
| AAD | `utf8(kid) + 0x00 + utf8(purpose)` |

`purpose` 是呼叫方自訂的用途標記（`urlparam`、`body`…），**加密與解密必須一致**，否則 AAD 不符。

## 3. 識別碼規則

| 項目 | 規則 |
|---|---|
| `kid` | `{systemCode}:{seq}`，不得含 `.`，長度 ≤ 64 |
| `purpose` | `^[a-z0-9_-]{1,32}$`，不得含 `\x00` |
| token | ≤ 8192 字元，超過直接拒絕 |

## 4. 錯誤碼

四種語言必須回傳同一組代碼：

| 代碼 | 意義 |
|---|---|
| `ERR_FORMAT` | 前綴、長度、版本位元組、base64url 非法、超長 |
| `ERR_UNKNOWN_KID` | kid 未登記、已退役、或前綴與金鑰不符 |
| `ERR_KEY` | 公鑰無效、不在曲線上、非 P-256 |
| `ERR_AUTH` | GCM 認證失敗（密文／tag／AAD 任一不符） |
| `ERR_STALE` | 快照超過 300 秒且刷新失敗 |
| `ERR_UNAVAILABLE` | 中央逾時或 5xx |
| `ERR_UNAUTHORIZED` | 403：未登記、已停用、憑證無效 |
| `ERR_POLICY_DISABLED` | 中央明確回傳「不加密」 |

**三條紅線**：認證失敗不重試、任何錯誤不得退回明文、不得回傳部分明文。

## 5. 版本生命週期

```
pending → active → decrypt_only → retired
```

| 狀態 | 可加密 | 可解密 |
|---|---|---|
| `pending` | 否 | 否 |
| `active` | 是 | 是 |
| `decrypt_only` | 否 | 是（5 分鐘） |
| `retired` | 否 | 否（私鑰已銷毀） |

輪替時：新版 `active`、舊版 `decrypt_only`，5 分鐘後 `retired`。
中央在下發的 `decrypt_versions` 白名單裡控制，**用戶端不做時間計算**。

## 6. 測試向量

`key-protocol-vectors/v1/vectors.json` 是規範性資料：

- 6 組正向：解密比對 + **固定隨機值重現密文**
- 11 組負向：必須回傳指定錯誤碼

四套 SDK 都必須全部通過：

```bash
go test ./keycrypto
node sdks/node/test/vectors.mjs
php sdks/php/test/vectors.php
java -cp out VectorTest        # 見 sdks/java/run-tests.ps1
```

修改 `vectors.json` 等同修改協定，需開新版本目錄（`v2/`）。
