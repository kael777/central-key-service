<?php
declare(strict_types=1);

namespace KeySdk;

/**
 * 網路層：輪詢 /sync、快照快取、私鑰取得、降級判斷。
 *
 * PHP 沒有常駐行程，業務請求不應直接呼叫中央；正式用法是由 cron 執行
 * `bin/key-sdk sync` 寫入本機快取，業務端只讀快取（見 README）。
 */
final class KeyClient
{
    public const MAX_STALENESS = 60;
    public const VERSION = '1.0.0';

    private array $cfg;
    private ?array $snapshot = null;
    private ?string $etag = null;
    /** @var array<string, \OpenSSLAsymmetricKey> */
    private array $keys = [];
    /** @var array<string, string> kid => PKCS8 DER（base64） */
    private array $keyDer = [];
    private bool $lastNotModified = false;

    public function __construct(array $cfg)
    {
        foreach (['base_url', 'system_code', 'cert', 'key'] as $f) {
            if (empty($cfg[$f])) {
                throw new \InvalidArgumentException("缺少設定：{$f}");
            }
        }
        $this->cfg = $cfg;
    }

    public function snapshot(): ?array
    {
        return $this->snapshot;
    }

    public function lastNotModified(): bool
    {
        return $this->lastNotModified;
    }

    /** 取得最新快照；304 時只更新時間戳。 */
    public function refresh(): array
    {
        $headers = [];
        if ($this->etag !== null) {
            $headers[] = 'If-None-Match: ' . $this->etag;
        }
        $res = $this->request('GET', '/api/v1/sync', null, $headers);
        $this->lastNotModified = $res['status'] === 304;

        if ($res['status'] === 304) {
            if ($this->snapshot !== null) {
                $this->snapshot['fetched_at'] = hrtime(true);
            }
            return $this->snapshot ?? [];
        }
        if ($res['status'] === 401 || $res['status'] === 403) {
            throw new KeyError(KeyError::UNAUTHORIZED, '未登記、已停用或憑證無效');
        }
        if ($res['status'] !== 200) {
            throw new KeyError(KeyError::UNAVAILABLE, '中央回應 ' . $res['status']);
        }
        $doc = json_decode($res['body'], true, 512, JSON_THROW_ON_ERROR);
        $this->etag = $res['headers']['etag'] ?? null;

        $peers = [];
        foreach ($doc['peers'] ?? [] as $name => $p) {
            $peers[$name] = ['kid' => $p['kid'], 'spki' => base64_decode($p['public_key'])];
        }
        $kids = [];
        foreach ($doc['self']['decrypt_versions'] ?? [] as $v) {
            $kids[] = $v['kid'];
        }

        $this->snapshot = [
            'mode' => $doc['self']['encryption']['mode'] ?? 'required',
            'policy_id' => $doc['self']['encryption']['policy_id'] ?? null,
            'peers' => $peers,
            'decrypt_kids' => $kids,
            'fetched_at' => hrtime(true),
        ];
        return $this->snapshot;
    }

    private function fresh(): array
    {
        if ($this->snapshot !== null && hrtime(true) - (int) $this->snapshot['fetched_at'] <= self::MAX_STALENESS * 1_000_000_000) {
            return $this->snapshot;
        }
        try {
            return $this->refresh();
        } catch (KeyError $e) {
            if ($this->snapshot !== null) {
                throw new KeyError(KeyError::STALE, '快照已過期且刷新失敗：' . $e->getMessage());
            }
            throw $e;
        }
    }

    /** 以對端系統的公鑰加密。 */
    public function encrypt(string $peerSystem, string $purpose, string $plaintext): string
    {
        $snap = $this->fresh();
        if (($snap['mode'] ?? 'required') === 'disabled') {
            throw new KeyError(KeyError::POLICY_DISABLED, '中央政策為不加密');
        }
        if (!isset($snap['peers'][$peerSystem])) {
            $snap = $this->refresh();
            if (!isset($snap['peers'][$peerSystem])) {
                throw new KeyError(KeyError::UNKNOWN_KID, '對端系統未登記：' . $peerSystem);
            }
        }
        $peer = $snap['peers'][$peerSystem];
        return KeyCrypto::encrypt($peer['spki'], $peer['kid'], $purpose, $plaintext);
    }

    /** 依密文版本取得對應私鑰並解密。 */
    public function decrypt(string $token, string $purpose): string
    {
        $t = KeyCrypto::parse($token);
        return KeyCrypto::decrypt($this->privateKey($t['kid']), $token, $purpose);
    }

    /** 取得（並快取）指定版本的私鑰。 */
    public function privateKey(string $kid): \OpenSSLAsymmetricKey
    {
        if (isset($this->keys[$kid])) {
            return $this->keys[$kid];
        }
        if ($this->snapshot !== null && !in_array($kid, $this->snapshot['decrypt_kids'], true)) {
            $this->refresh();
            if (!in_array($kid, $this->snapshot['decrypt_kids'] ?? [], true)) {
                throw new KeyError(KeyError::UNKNOWN_KID, 'kid 不在授權清單：' . $kid);
            }
        }
        $der = $this->fetchPrivateKeyDer($kid);
        $pem = KeyCrypto::privatePemFromDer($der);
        $key = @openssl_pkey_get_private($pem);
        if ($key === false) {
            throw new KeyError(KeyError::KEY, '私鑰解析失敗');
        }
        $this->keys[$kid] = $key;
        return $key;
    }

    /** 取得指定版本的 PKCS8 DER（未包裝）。 */
    public function fetchPrivateKeyDer(string $kid): string
    {
        if (isset($this->keyDer[$kid])) {
            return base64_decode($this->keyDer[$kid]);
        }
        $res = $this->request('POST', '/api/v1/self/private-key', json_encode(['kid' => $kid]));
        if ($res['status'] === 401 || $res['status'] === 403) {
            throw new KeyError(KeyError::UNAUTHORIZED, '無權取得該私鑰');
        }
        if ($res['status'] === 404) {
            throw new KeyError(KeyError::UNKNOWN_KID, 'kid 不存在：' . $kid);
        }
        if ($res['status'] !== 200) {
            throw new KeyError(KeyError::UNAVAILABLE, '私鑰端點回應 ' . $res['status']);
        }
        $doc = json_decode($res['body'], true, 512, JSON_THROW_ON_ERROR);
        $derB64 = $doc['private_key_b64'];
        $this->keyDer[$kid] = $derB64;
        return base64_decode($derB64);
    }

    /** 快照與私鑰的匯出格式，供 cron 寫入本機快取。 */
    public function exportCache(): array
    {
        $peers = [];
        foreach ($this->snapshot['peers'] ?? [] as $name => $p) {
            $peers[$name] = ['kid' => $p['kid'], 'spki' => base64_encode($p['spki'])];
        }
        return [
            'version' => self::VERSION,
            'system_code' => $this->cfg['system_code'],
            'generated_at' => time(),
            'snapshot' => [
                'mode' => $this->snapshot['mode'] ?? 'required',
                'decrypt_kids' => $this->snapshot['decrypt_kids'] ?? [],
                'fetched_at' => $this->snapshot['fetched_at'] ?? hrtime(true),
                'peers' => $peers,
            ],
            'keys' => $this->keyDer,
        ];
    }

    private function request(string $method, string $path, ?string $body = null, array $extraHeaders = []): array
    {
        $headerLines = array_merge(
            [
                'User-Agent: key-sdk-php/' . self::VERSION,
                'Accept: application/json',
                'Connection: close',
            ],
            $extraHeaders
        );
        if ($body !== null) {
            $headerLines[] = 'Content-Type: application/json';
            $headerLines[] = 'Content-Length: ' . strlen($body);
        }
        $ctx = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headerLines),
                'content' => $body ?? '',
                'ignore_errors' => true,
                'timeout' => 10,
            ],
            'ssl' => array_filter([
                'local_cert' => $this->cfg['cert'],
                'local_pk' => $this->cfg['key'],
                'cafile' => $this->cfg['ca'] ?? null,
                'verify_peer' => true,
                'verify_peer_name' => true,
            ], static fn ($v) => $v !== null),
        ]);

        $http_response_header = [];
        $resp = @file_get_contents(rtrim($this->cfg['base_url'], '/') . $path, false, $ctx);
        $rawHeaders = $http_response_header ?? [];
        if ($resp === false && $rawHeaders === []) {
            $err = error_get_last();
            throw new KeyError(KeyError::UNAVAILABLE, '連線中央失敗：' . ($err['message'] ?? '未知錯誤'));
        }
        $status = 0;
        $parsed = [];
        foreach ($rawHeaders as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1];
                continue;
            }
            if (str_contains($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $parsed[strtolower(trim($k))] = trim($v);
            }
        }
        return ['status' => $status, 'body' => $resp === false ? '' : $resp, 'headers' => $parsed];
    }
}
