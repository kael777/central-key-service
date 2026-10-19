<?php
declare(strict_types=1);

namespace KeySdk;

final class KeyError extends \RuntimeException
{
    public const FORMAT = 'ERR_FORMAT';
    public const UNKNOWN_KID = 'ERR_UNKNOWN_KID';
    public const KEY = 'ERR_KEY';
    public const AUTH = 'ERR_AUTH';
    public const STALE = 'ERR_STALE';
    public const UNAVAILABLE = 'ERR_UNAVAILABLE';
    public const UNAUTHORIZED = 'ERR_UNAUTHORIZED';
    public const POLICY_DISABLED = 'ERR_POLICY_DISABLED';

    public function __construct(public readonly string $keyCode, string $message = '')
    {
        parent::__construct($message !== '' ? $message : $keyCode);
    }
}
