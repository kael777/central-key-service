<?php
declare(strict_types=1);

namespace KeySdk;

/**
 * 讀取 cron 產生的本機快取，讓業務請求不必連中央。
 *
 * 用法：
 *   $cache = KeyCache::load('/var/cache/key-sdk/snapshot.json');
 *   $plain = KeyCache::decrypt($cache, $token, 'urlparam');
 */
final class KeyCache
{
    /** 讀取快取檔；過期時回傳 null（呼叫端應視為需要重新同步）。 */
    public static function load(string $path, int $maxStaleness = 300): ?array
    {
        if (!is_file($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['snapshot']['fetched_at'])) {
            return null;
        }
        if (time() - (int) $data['snapshot']['fetched_at'] > $maxStaleness) {
            return null;
        }
        return $data;
    }

    /** 以快取中的私鑰解密。 */
    public static function decrypt(array $cache, string $token, string $purpose): string
    {
        $t = KeyCrypto::parse($token);
        $kid = $t['kid'];
        if (!isset($cache['keys'][$kid])) {
            throw new KeyError(KeyError::UNKNOWN_KID, '快取中沒有此版本私鑰：' . $kid);
        }
        $pem = KeyCrypto::privatePemFromDer(base64_decode($cache['keys'][$kid]));
        $key = @openssl_pkey_get_private($pem);
        if ($key === false) {
            throw new KeyError(KeyError::KEY, '快取私鑰解析失敗');
        }
        return KeyCrypto::decrypt($key, $token, $purpose);
    }

    /** 取得對端公鑰（用於加密，同樣不需連中央）。 */
    public static function peerSpki(array $cache, string $peerSystem): array
    {
        $p = $cache['snapshot']['peers'][$peerSystem] ?? null;
        if ($p === null) {
            throw new KeyError(KeyError::UNKNOWN_KID, '快取中沒有對端系統：' . $peerSystem);
        }
        return ['kid' => $p['kid'], 'spki' => base64_decode($p['spki'])];
    }
}
