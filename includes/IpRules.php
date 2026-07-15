<?php

namespace NexaPressAccessGuard;

/*
 * 許可IP・拒否IPの判定
 */
class IpRules
{
    /*
     * 現在接続しているIPを取得
     */
    public static function currentIp(): string
    {
        $ip = trim(
            (string)($_SERVER['REMOTE_ADDR'] ?? '')
        );

        if (
            filter_var(
                $ip,
                FILTER_VALIDATE_IP
            ) === false
        ) {
            return '';
        }

        return $ip;
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
        if (
            $ip === '' ||
            filter_var(
                $ip,
                FILTER_VALIDATE_IP
            ) === false
        ) {
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
                trim($savedIp) === $ip
            ) {
                return true;
            }
        }

        return false;
    }
}