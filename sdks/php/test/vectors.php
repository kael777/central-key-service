<?php
declare(strict_types=1);

// 以 vectors.json 驗證 PHP SDK
require __DIR__ . '/../src/KeyError.php';
require __DIR__ . '/../src/KeyCrypto.php';

use KeySdk\KeyCrypto;
use KeySdk\KeyError;

function findVectors(): string
{
    if ($p = getenv('KEY_VECTORS')) {
        return $p;
    }
    $dir = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $dir . '/key-protocol-vectors/v1/vectors.json';
        if (file_exists($p)) {
            return $p;
        }
        $dir = dirname($dir);
    }
    fwrite(STDERR, "找不到 vectors.json，請設定 KEY_VECTORS\n");
    exit(2);
}

$doc = json_decode(file_get_contents(findVectors()), true, 512, JSON_THROW_ON_ERROR);
$pass = 0;
$fail = 0;

function check(string $name, callable $fn): void
{
    global $pass, $fail;
    try {
        $fn();
        $pass++;
        echo "  PASS  {$name}\n";
    } catch (Throwable $e) {
        $fail++;
        echo "  FAIL  {$name}  → {$e->getMessage()}\n";
    }
}

$keys = [];
foreach ($doc['keys'] as $k) {
    $key = KeyCrypto::privateKeyFromScalar(hex2bin($k['d_hex']));
    $spki = KeyCrypto::publicDerFromKey($key);
    if (base64_encode($spki) !== $k['spki_b64']) {
        fwrite(STDERR, "SPKI 不符：{$k['kid']}\n");
        exit(2);
    }
    $keys[$k['kid']] = ['key' => $key, 'spki' => $spki];
}

echo "[正向：解密]\n";
foreach ($doc['positive'] as $v) {
    check($v['name'], function () use ($v, $keys) {
        $pt = KeyCrypto::decrypt($keys[$v['kid']]['key'], $v['token'], $v['purpose']);
        if (base64_encode($pt) !== $v['plaintext_b64']) {
            throw new RuntimeException('明文不一致');
        }
    });
}

echo "\n[正向：固定隨機值重現密文]\n";
foreach ($doc['positive'] as $v) {
    check($v['name'], function () use ($v, $keys) {
        $token = KeyCrypto::encrypt(
            $keys[$v['kid']]['spki'],
            $v['kid'],
            $v['purpose'],
            base64_decode($v['plaintext_b64']),
            $v['eph_d_hex'],
            $v['iv_hex']
        );
        if ($token !== $v['token']) {
            throw new RuntimeException('密文與向量不符');
        }
    });
}

echo "\n[負向：必須回傳指定錯誤碼]\n";
foreach ($doc['negative'] as $n) {
    check($n['name'], function () use ($n, $keys) {
        if (!isset($keys[$n['kid']])) {
            if ($n['expect_error'] !== KeyError::UNKNOWN_KID) {
                throw new RuntimeException("預期 {$n['expect_error']}");
            }
            return;
        }
        try {
            KeyCrypto::decrypt($keys[$n['kid']]['key'], $n['token'], $n['purpose']);
        } catch (KeyError $e) {
            if ($e->keyCode !== $n['expect_error']) {
                throw new RuntimeException("預期 {$n['expect_error']}，實際 {$e->keyCode}");
            }
            return;
        }
        throw new RuntimeException('預期錯誤但解密成功');
    });
}

echo "\n結果：PASS {$pass} / FAIL {$fail}\n";
exit($fail === 0 ? 0 : 1);
