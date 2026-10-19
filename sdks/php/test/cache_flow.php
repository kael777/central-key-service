<?php
declare(strict_types=1);

// PHP 專屬鏈路驗證：cron 同步 → 本機快取 → 業務端只讀快取解密
require __DIR__ . '/../src/KeyError.php';
require __DIR__ . '/../src/KeyCrypto.php';
require __DIR__ . '/../src/KeyClient.php';
require __DIR__ . '/../src/KeyCache.php';

use KeySdk\KeyCache;
use KeySdk\KeyClient;

$base = $argv[1] ?? 'https://127.0.0.1:8443';
$certs = __DIR__ . '/../../../go-key-sdk/certs';
$cacheDir = sys_get_temp_dir() . '/key-sdk-cache-' . getmypid();

@mkdir($cacheDir, 0700, true);

$mk = static fn (string $code) => new KeyClient([
    'base_url' => $base,
    'system_code' => $code,
    'cert' => "{$certs}/clients/{$code}.crt",
    'key' => "{$certs}/clients/{$code}.key",
    'ca' => "{$certs}/ca.crt",
]);

// 1) A 產生密文
$payload = '訂單編號=A123456&金額=1000';
$token = $mk('SYS-A')->encrypt('SYS-B', 'urlparam', $payload);
echo 'A encrypt → ' . substr($token, 0, 24) . "...\n";

// 2) 模擬 cron：執行 CLI 同步到本機快取
$configFile = "{$cacheDir}/config.php";
file_put_contents($configFile, '<?php return ' . var_export([
    'base_url' => $base,
    'system_code' => 'SYS-B',
    'cert' => "{$certs}/clients/SYS-B.crt",
    'key' => "{$certs}/clients/SYS-B.key",
    'ca' => "{$certs}/ca.crt",
    'cache_dir' => $cacheDir,
], true) . ';');

$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/../bin/key-sdk')
    . ' sync --config=' . escapeshellarg($configFile) . ' 2>&1';
exec($cmd, $out, $code);
echo 'cron sync  → ' . implode(' ', $out) . "（exit {$code}）\n";
if ($code !== 0) {
    fwrite(STDERR, "FAIL: CLI 同步失敗\n");
    exit(1);
}

// 3) 業務端：只讀快取，不連中央
$cache = KeyCache::load("{$cacheDir}/snapshot.json");
if ($cache === null) {
    fwrite(STDERR, "FAIL: 快取無法載入\n");
    exit(1);
}
$plain = KeyCache::decrypt($cache, $token, 'urlparam');
echo "cache decrypt → \"{$plain}\"\n";

if ($plain !== $payload) {
    fwrite(STDERR, "FAIL: 明文不符\n");
    exit(1);
}

// 4) check 模式
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/../bin/key-sdk')
    . ' check --config=' . escapeshellarg($configFile) . ' 2>&1', $out2, $code2);
echo 'check      → ' . implode(' ', $out2) . "（exit {$code2}）\n";

array_map('unlink', glob("{$cacheDir}/*") ?: []);
@rmdir($cacheDir);

echo "PASS  PHP cron 快取鏈路成功\n";
exit(0);
