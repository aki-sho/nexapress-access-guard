<?php

namespace NexaPressAccessGuard;

/*
 * 許可IP・拒否IPの判定
 */
class IpRules
{
    /* IPv6の省略形・大文字小文字・IPv4射影表記を統一する。 */
    public static function normalize(string $ip): ?string
    {
        $ip = trim($ip);

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = inet_pton($ip);

        if ($packed === false) {
            return null;
        }

        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $packed = substr($packed, 12);
        }

        $normalized = inet_ntop($packed);

        return $normalized === false ? null : strtolower($normalized);
    }

    /*
     * 現在接続しているIPを取得
     */
    public static function currentIp(): string
    {
        return self::resolve($_SERVER, Settings::get('trusted_proxy'));
    }

    public static function normalizeNetwork(string $network): ?string
    {
        $parts = explode('/', trim($network));
        $ip = self::normalize($parts[0]);

        if ($ip === null || count($parts) > 2) {
            return null;
        }

        if (count($parts) === 1) {
            return $ip;
        }

        $bytes = inet_pton($ip);
        $maximum = strlen($bytes) * 8;

        if (!ctype_digit($parts[1]) || (int)$parts[1] < 1 || (int)$parts[1] > $maximum ||
            strlen(inet_pton(trim($parts[0]))) !== strlen($bytes)) {
            return null;
        }

        $prefix = (int)$parts[1];
        $masked = '';

        for ($index = 0; $index < strlen($bytes); $index++) {
            $bits = max(0, min(8, $prefix - $index * 8));
            $masked .= chr(ord($bytes[$index]) & (256 - (1 << (8 - $bits))));
        }

        return inet_ntop($masked) . '/' . $prefix;
    }

    public static function inNetwork(string $ip, string $network): bool
    {
        $ip = self::normalize($ip);
        $network = self::normalizeNetwork($network);

        if ($ip === null || $network === null) {
            return false;
        }

        $parts = explode('/', $network);
        $address = inet_pton($ip);
        $base = inet_pton($parts[0]);

        if (strlen($address) !== strlen($base)) {
            return false;
        }

        $prefix = isset($parts[1]) ? (int)$parts[1] : strlen($base) * 8;
        $whole = intdiv($prefix, 8);
        $remaining = $prefix % 8;

        return substr($address, 0, $whole) === substr($base, 0, $whole) &&
            ($remaining === 0 || ((ord($address[$whole]) ^ ord($base[$whole])) & (255 << (8 - $remaining))) === 0);
    }

    public static function resolve(array $server, array $setting): string
    {
        $peer = self::normalize((string)($server['REMOTE_ADDR'] ?? '')) ?? '';
        $trusted = static function (string $ip) use ($setting): bool {
            foreach ($setting['proxies'] as $network) {
                if (self::inNetwork($ip, $network)) {
                    return true;
                }
            }

            return false;
        };

        if (!$setting['enabled'] || !$trusted($peer)) {
            return $peer;
        }

        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $setting['header']));
        $header = (string)($server[$key] ?? '');

        if ($header === '' || strlen($header) > 8192) {
            return '';
        }

        $chain = explode(',', $header);

        if (count($chain) > 32 || ($setting['header'] !== 'x-forwarded-for' && count($chain) !== 1)) {
            return '';
        }

        foreach ($chain as &$address) {
            $address = self::normalize($address);

            if ($address === null) {
                return '';
            }
        }
        unset($address);

        // 右端の直近プロキシからたどり、最初の信頼されていないIPを採用する。
        $current = $peer;

        foreach (array_reverse($chain) as $address) {
            if (!$trusted($current)) {
                break;
            }

            $current = $address;
        }

        return $current;
    }

    /*
     * 許可IPか確認
     */
    public static function isAllowed(
        ?string $ip = null
    ): bool {
        return self::contains(
            'allowed_ips',
            $ip ?? self::currentIp()
        );
    }

    /*
     * 拒否IPか確認
     */
    public static function isDenied(
        ?string $ip = null
    ): bool {
        return self::contains(
            'denied_ips',
            $ip ?? self::currentIp()
        );
    }

    /*
     * 指定したIPが一覧に含まれているか確認
     */
    private static function contains(
        string $section,
        string $ip
    ): bool {
        $ip = self::normalize($ip);

        if ($ip === null) {
            return false;
        }

        $ips = Settings::get(
            $section,
            []
        );

        if (!is_array($ips)) {
            return false;
        }

        foreach ($ips as $savedIp) {
            if (
                is_string($savedIp) &&
                self::normalize($savedIp) === $ip
            ) {
                return true;
            }
        }

        return false;
    }
}
