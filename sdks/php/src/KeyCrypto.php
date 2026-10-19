<?php
declare(strict_types=1);

namespace KeySdk;

/**
 * cms-key 協定 v1：純函式層（無網路）。
 *
 * 密文格式：KEY1.{kid}.{base64url(0x01 | eph_spki_der(91) | iv(12) | ciphertext | tag(16))}
 */
final class KeyCrypto
{
    public const PREFIX = 'KEY1.';
    public const SPKI_LEN = 91;
    public const IV_LEN = 12;
    public const TAG_LEN = 16;
    public const KEY_LEN = 32;
    public const MAX_TOKEN_LEN = 8192;

    private const KID_RE = '/^[A-Za-z0-9_:-]{1,64}$/';
    private const PURPOSE_RE = '/^[a-z0-9_-]{1,32}$/';
    private const B64URL_RE = '/^[A-Za-z0-9_-]+$/';

    public static function validKid(string $kid): bool
    {
        return (bool) preg_match(self::KID_RE, $kid);
    }

    public static function validPurpose(string $purpose): bool
    {
        return (bool) preg_match(self::PURPOSE_RE, $purpose);
    }

    /** 結構解析，不接觸金鑰。 */
    public static function parse(string $token): array
    {
        if (strlen($token) > self::MAX_TOKEN_LEN) {
            throw new KeyError(KeyError::FORMAT, 'token 過長');
        }
        if (!str_starts_with($token, self::PREFIX)) {
            throw new KeyError(KeyError::FORMAT, '缺少前綴');
        }
        $rest = substr($token, strlen(self::PREFIX));
        $i = strpos($rest, '.');
        if ($i === false || $i === 0) {
            throw new KeyError(KeyError::FORMAT, 'kid 分隔錯誤');
        }
        $kid = substr($rest, 0, $i);
        $body = substr($rest, $i + 1);
        if (!self::validKid($kid)) {
            throw new KeyError(KeyError::FORMAT, 'kid 非法');
        }
        if (!preg_match(self::B64URL_RE, $body)) {
            throw new KeyError(KeyError::FORMAT, 'payload 含非法字元');
        }
        $payload = base64_decode(strtr($body, '-_', '+/'), true);
        if ($payload === false) {
            throw new KeyError(KeyError::FORMAT, 'payload 解碼失敗');
        }
        if (strlen($payload) < 1 + self::SPKI_LEN + self::IV_LEN + self::TAG_LEN) {
            throw new KeyError(KeyError::FORMAT, 'payload 過短');
        }
        if (ord($payload[0]) !== 1) {
            throw new KeyError(KeyError::FORMAT, '未知版本位元組');
        }
        $spki = substr($payload, 1, self::SPKI_LEN);
        $iv = substr($payload, 1 + self::SPKI_LEN, self::IV_LEN);
        $ct = substr($payload, 1 + self::SPKI_LEN + self::IV_LEN);

        return ['kid' => $kid, 'spki' => $spki, 'iv' => $iv, 'ciphertext' => $ct];
    }

    /**
     * 加密。$ephDHex／$ivHex 供測試注入固定隨機值；生產環境請留 null。
     */
    public static function encrypt(
        string $spkiDer,
        string $kid,
        string $purpose,
        string $plaintext,
        ?string $ephDHex = null,
        ?string $ivHex = null
    ): string {
        if (!self::validKid($kid)) {
            throw new KeyError(KeyError::FORMAT, 'kid 非法');
        }
        if (!self::validPurpose($purpose)) {
            throw new KeyError(KeyError::FORMAT, 'purpose 非法');
        }
        $recipient = @openssl_pkey_get_public(self::derToPem($spkiDer));
        if ($recipient === false) {
            throw new KeyError(KeyError::KEY, '對端公鑰無效');
        }
        $eph = self::ephemeral($ephDHex);
        $shared = @openssl_pkey_derive($recipient, $eph['key']);
        if ($shared === false || strlen($shared) !== 32) {
            throw new KeyError(KeyError::KEY, 'ECDH 失敗');
        }
        $key = self::deriveKey($shared, $kid, $purpose);

        $iv = $ivHex !== null ? hex2bin($ivHex) : random_bytes(self::IV_LEN);
        if (strlen($iv) !== self::IV_LEN) {
            throw new KeyError(KeyError::FORMAT, 'IV 需為 12 bytes');
        }
        $tag = '';
        $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, self::aad($kid, $purpose), self::TAG_LEN);
        if ($ct === false) {
            throw new KeyError(KeyError::KEY, 'AES-GCM 加密失敗');
        }

        $payload = "\x01" . $eph['spki'] . $iv . $ct . $tag;
        return self::PREFIX . $kid . '.' . rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
    }

    /** 解密。$purpose 必須與加密時一致。 */
    public static function decrypt($privateKey, string $token, string $purpose): string
    {
        if (!self::validPurpose($purpose)) {
            throw new KeyError(KeyError::FORMAT, 'purpose 非法');
        }
        $t = self::parse($token);
        $ephPub = @openssl_pkey_get_public(self::derToPem($t['spki']));
        if ($ephPub === false) {
            throw new KeyError(KeyError::KEY, '臨時公鑰無效');
        }
        $priv = is_string($privateKey) ? @openssl_pkey_get_private($privateKey) : $privateKey;
        if ($priv === false || $priv === null) {
            throw new KeyError(KeyError::KEY, '私鑰無效');
        }
        $shared = @openssl_pkey_derive($ephPub, $priv);
        if ($shared === false || strlen($shared) !== 32) {
            throw new KeyError(KeyError::KEY, 'ECDH 失敗');
        }
        $key = self::deriveKey($shared, $t['kid'], $purpose);

        $ct = $t['ciphertext'];
        $body = substr($ct, 0, -self::TAG_LEN);
        $tag = substr($ct, -self::TAG_LEN);
        $pt = @openssl_decrypt($body, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $t['iv'], $tag, self::aad($t['kid'], $purpose));
        if ($pt === false) {
            throw new KeyError(KeyError::AUTH, 'GCM 認證失敗');
        }

        return $pt;
    }

    /**
     * 由 32 bytes 私鑰純量建立私鑰物件。
     * 回傳 OpenSSLAsymmetricKey（不轉 PEM，避免依賴 openssl.cnf）。
     */
    public static function privateKeyFromScalar(string $d): \OpenSSLAsymmetricKey
    {
        if (strlen($d) !== self::KEY_LEN) {
            throw new KeyError(KeyError::KEY, '私鑰需為 32 bytes');
        }
        $key = @openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'ec' => ['curve_name' => 'prime256v1', 'd' => $d],
        ]);
        if ($key === false) {
            throw new KeyError(KeyError::KEY, '無法由純量建立私鑰');
        }
        return $key;
    }

    /** 由私鑰物件或 PEM 取得公開金鑰的 SPKI DER（91 bytes）。 */
    public static function publicDerFromKey($key): string
    {
        if (is_string($key)) {
            $key = @openssl_pkey_get_private($key) ?: @openssl_pkey_get_public($key);
        }
        if (!$key instanceof \OpenSSLAsymmetricKey) {
            throw new KeyError(KeyError::KEY, '金鑰無效');
        }
        $det = openssl_pkey_get_details($key);
        if ($det === false || !isset($det['key'])) {
            throw new KeyError(KeyError::KEY, '無法取得公開金鑰');
        }
        return self::pemToDer($det['key']);
    }

    /** 將 PKCS8 DER 私鑰轉為 PEM。 */
    public static function privatePemFromDer(string $der): string
    {
        return self::derToPem($der, 'PRIVATE KEY');
    }

    public static function pemToDer(string $pem): string
    {
        $body = preg_replace('/-----[^-]+-----/', '', $pem);
        $der = base64_decode(preg_replace('/\s+/', '', $body), true);
        if ($der === false) {
            throw new KeyError(KeyError::KEY, 'PEM 解析失敗');
        }
        return $der;
    }

    public static function derToPem(string $der, string $label = 'PUBLIC KEY'): string
    {
        return "-----BEGIN {$label}-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END {$label}-----\n";
    }

    private static function ephemeral(?string $ephDHex): array
    {
        if ($ephDHex !== null) {
            $d = hex2bin($ephDHex);
            $key = @openssl_pkey_new([
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'ec' => ['curve_name' => 'prime256v1', 'd' => $d],
            ]);
        } else {
            $key = @openssl_pkey_new([
                'private_key_type' => OPENSSL_KEYTYPE_EC,
                'ec' => ['curve_name' => 'prime256v1'],
            ]);
        }
        if ($key === false) {
            throw new KeyError(KeyError::KEY, '建立臨時金鑰失敗');
        }
        $det = openssl_pkey_get_details($key);
        return ['key' => $key, 'spki' => self::pemToDer($det['key'])];
    }

    private static function deriveKey(string $shared, string $kid, string $purpose): string
    {
        return hash_hkdf('sha256', $shared, self::KEY_LEN, "cms-key-v1|{$kid}|{$purpose}");
    }

    private static function aad(string $kid, string $purpose): string
    {
        return $kid . "\x00" . $purpose;
    }
}
