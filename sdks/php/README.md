# PHP SDK（cms-key v1）

PHP 8.1+，只需 `openssl` 與 `hash` 擴充。

## 驗證

```bash
composer test        # 或 php test/vectors.php
```

實測：`PASS 23 / FAIL 0`。

## 使用

```php
require 'src/KeyError.php';
require 'src/KeyCrypto.php';

use KeySdk\KeyCrypto;

$token = KeyCrypto::encrypt($spkiDer, 'SYS-B:3', 'urlparam', $plaintext);
$pt    = KeyCrypto::decrypt($privateKeyObject, $token, 'urlparam');
```

`KeyCrypto::privateKeyFromScalar($d)` 回傳 `OpenSSLAsymmetricKey`，可直接傳給 `decrypt`；
從伺服器取得的 PKCS8 DER 可用 `KeyCrypto::privatePemFromDer($der)` 轉成 PEM。

## 注意

- **不要用 `openssl_pkey_export()`**：Windows 版 PHP 需要 `openssl.cnf`，沒有會直接失敗。
  本 SDK 刻意不呼叫它，改用金鑰物件傳遞。
- GCM tag 由 `openssl_encrypt()` 的第七、八參數輸出／帶入。
- 錯誤以 `KeyError::$keyCode` 取得。

## 給 PHP-FPM 的提醒

PHP 沒有常駐行程。生產環境應由 cron 每分鐘執行同步任務，把快照與私鑰寫入本機快取
（見 `RUNBOOK` 與技術方案第 12.3 節），**不要在請求中同步呼叫中央**。

## Client 與 cron（PHP 沒有常駐行程）

```php
$client = new KeySdk\KeyClient([
    'base_url' => 'https://key.internal',
    'system_code' => 'SYS-B',
    'cert' => '/etc/key-sdk/client.crt',
    'key'  => '/etc/key-sdk/client.key',
    'ca'   => '/etc/key-sdk/ca.crt',
]);

$token = $client->encrypt('SYS-A', 'urlparam', $data);
$plain = $client->decrypt($token, 'urlparam');
```

正式用法是 **cron 每分鐘同步**，業務請求只讀快取：

```
* * * * * php /opt/key-sdk/bin/key-sdk sync --config=/etc/key-sdk.php
```

```php
$cache = KeySdk\KeyCache::load('/var/cache/key-sdk/snapshot.json');
$plain = KeySdk\KeyCache::decrypt($cache, $token, 'urlparam');
```

`key-sdk check` 回傳離開碼：0 正常、2 快取過期、3 未授權、4 連線失敗，可直接接監控。

驗證：

```bash
php test/client_smoke.php https://127.0.0.1:8443
php test/cache_flow.php  https://127.0.0.1:8443
```