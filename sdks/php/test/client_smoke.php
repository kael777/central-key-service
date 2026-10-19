<?php
declare(strict_types=1);

// 端到端驗證：A 加密 → B 解密，走真實 mTLS 與中央服務
require __DIR__ . '/../src/KeyError.php';
require __DIR__ . '/../src/KeyCrypto.php';
require __DIR__ . '/../src/KeyClient.php';

use KeySdk\KeyClient;
use KeySdk\KeyError;

$base = $argv[1] ?? 'https://127.0.0.1:8443';
$certs = $argv[2] ?? __DIR__ . '/../../../go-key-sdk/certs';

$mk = static fn (string $code) => new KeyClient([
    'base_url' => $base,
    'system_code' => $code,
    'cert' => "{$certs}/clients/{$code}.crt",
    'key' => "{$certs}/clients/{$code}.key",
    'ca' => "{$certs}/ca.crt",
]);

try {
    $a = $mk('SYS-A');
    $b = $mk('SYS-B');

    $payload = '訂單編號=A123456&金額=1000';
    $token = $a->encrypt('SYS-B', 'urlparam', $payload);
    echo 'A encrypt → ' . substr($token, 0, 24) . '...（' . strlen($token) . " 字元）\n";

    $plain = $b->decrypt($token, 'urlparam');
    echo "B decrypt → \"{$plain}\"\n";
    if ($plain !== $payload) {
        throw new RuntimeException('明文不符');
    }

    try {
        $b->decrypt($token, 'body');
        throw new RuntimeException('purpose 不符應該失敗');
    } catch (KeyError $e) {
        if ($e->keyCode !== KeyError::AUTH) {
            throw new RuntimeException('預期 ERR_AUTH，實際 ' . $e->keyCode);
        }
    }

    $sa = $a->snapshot();
    echo "snapshot A: mode={$sa['mode']} peers=" . count($sa['peers']) . "\n";
    if ($b->snapshot() === null) {
        $b->refresh();
    }
    echo 'snapshot B: decrypt_versions=' . count($b->snapshot()['decrypt_kids']) . "\n";
    echo "PASS  PHP Client 端到端成功\n";
    exit(0);
} catch (Throwable $e) {
    fwrite(STDERR, 'FAIL: ' . $e->getMessage() . "\n");
    exit(1);
}
