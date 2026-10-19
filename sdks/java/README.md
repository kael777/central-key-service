# Java SDK（cms-key v1）

JDK 17+，**零第三方依賴**（HKDF 與 EC 標量乘法自行實作，因為 JDK 沒有公開 API）。

## 驗證

```bash
.\run-tests.ps1          # 或：javac + java，見下方
```

實測：`PASS 24 / FAIL 0`。

手動編譯：

```bash
mkdir -p out
javac -encoding UTF-8 -d out $(find src -name '*.java')
javac -encoding UTF-8 -cp out -d out test/VectorTest.java
java -cp out VectorTest ../../key-protocol-vectors/v1/vectors.json
```

## 使用

```java
import keysdk.KeyCrypto;

// 純函式層
String token = KeyCrypto.encrypt(spkiDer, "SYS-B:3", "urlparam", plaintext);
byte[] pt = KeyCrypto.decrypt(privateKey, token, "urlparam");

// 解析
Token t = KeyCrypto.parse(token); // kid / ephemeralSpki / iv / ciphertext
```

錯誤以 `KeyError.code()` 取得，與其他語言同一組代碼。

## 兩個 JDK 坑（已處理）

1. **沒有 HKDF**：用 `Mac(HmacSHA256)` 實作 RFC 5869，salt 取 32 bytes 零。
2. **沒有「私鑰標量 → 公鑰」API**：測試向量要求用固定臨時私鑰重現密文，因此自行實作
   P-256 仿射點運算（`EcMath`）。生產路徑仍用 `KeyPairGenerator`，不經過這段程式碼。

若團隊允許引入 BouncyCastle，可換掉上述兩處；但目前的實作沒有任何外部依賴。

## Client（會去中央拿鑰匙）

```java
KeyClient client = KeyClient.config()
    .baseUrl("https://key.internal")
    .systemCode("SYS-A")
    .cert("/etc/key-sdk/client.crt", "/etc/key-sdk/client.key")
    .ca("/etc/key-sdk/ca.crt")
    .build();

String token = client.encrypt("SYS-B", "urlparam", params);
byte[] plain = client.decrypt(token, "urlparam");
```

Client 內部處理：`/sync` 輪詢（ETag/304）、快照快取、300 秒過期判斷、
私鑰按 kid 取得並快取、403/404/5xx 映射、失敗不降級。

驗證（需先啟動中央服務）：

```bash
javac -encoding UTF-8 -cp out -d out test/ClientSmoke.java
java -cp out ClientSmoke https://127.0.0.1:8443 ../../go-key-sdk/certs
```