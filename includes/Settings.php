<?php

namespace NexaPressAccessGuard;

use RuntimeException;

/*
 * Access Guardの設定管理
 */
class Settings
{
    /*
     * 初期設定
     */
    public static function defaults(): array
    {
        return [
            'login_page_access' => [
                'enabled' => false,
            ],

            'admin_page_access' => [
                'enabled' => false,
            ],

            'login_url' => [
                'enabled' => false,
                'slug' => 'secure-login',
            ],

            'login_lock' => [
                'enabled' => false,
                'attempts' => 5,
                'duration' => 30,
            ],

            'fail_once' => [
                'enabled' => false,
                'count' => 1,
            ],

            'allowed_ips' => [],

            'denied_ips' => [],
        ];
    }

    /*
     * 全設定を取得
     */
    public static function all(): array
    {
        $defaults = self::defaults();
        $path = self::settingsPath();

        if (!is_file($path)) {
            return $defaults;
        }

        $json = file_get_contents($path);

        if ($json === false) {
            return $defaults;
        }

        $savedSettings = json_decode($json, true);

        if (!is_array($savedSettings)) {
            return $defaults;
        }

        return array_replace_recursive(
            $defaults,
            $savedSettings
        );
    }

    /*
     * 指定した設定項目を取得
     */
    public static function get(
        string $section,
        mixed $default = null
    ): mixed {
        $settings = self::all();

        return $settings[$section] ?? $default;
    }

    /*
     * 指定した設定項目だけを保存
     */
    public static function saveSection(
        string $section,
        mixed $value
    ): void {
        $defaults = self::defaults();

        if (!array_key_exists($section, $defaults)) {
            throw new RuntimeException(
                '保存できない設定項目です。'
            );
        }

        $settings = self::all();
        $settings[$section] = $value;

        self::write($settings);
    }

    /*
     * IPを追加
     */
    public static function addIp(
        string $section,
        string $ip
    ): void {
        self::validateIpSection($section);

        $ips = self::get($section, []);

        if (!is_array($ips)) {
            $ips = [];
        }

        if (!in_array($ip, $ips, true)) {
            $ips[] = $ip;
        }

        sort($ips);

        self::saveSection($section, $ips);
    }

    /*
     * IPを削除
     */
    public static function removeIp(
        string $section,
        string $ip
    ): void {
        self::validateIpSection($section);

        $ips = self::get($section, []);

        if (!is_array($ips)) {
            $ips = [];
        }

        $ips = array_values(
            array_filter(
                $ips,
                static function (string $savedIp) use ($ip): bool {
                    return $savedIp !== $ip;
                }
            )
        );

        self::saveSection($section, $ips);
    }

    /*
     * 保存結果のメッセージを登録
     */
    public static function setNotice(
        string $message,
        string $type = 'success'
    ): void {
        $_SESSION['access_guard_notice'] = [
            'message' => $message,
            'type' => $type,
        ];
    }

    /*
     * 保存結果のメッセージを取得して削除
     */
    public static function pullNotice(): ?array
    {
        $notice =
            $_SESSION['access_guard_notice'] ?? null;

        unset($_SESSION['access_guard_notice']);

        return is_array($notice) ? $notice : null;
    }

    /*
     * 設定ファイルへ書き込む
     */
    private static function write(array $settings): void
    {
        $path = self::settingsPath();
        $directory = dirname($path);

        if (
            !is_dir($directory) &&
            !mkdir($directory, 0755, true)
        ) {
            throw new RuntimeException(
                '設定保存フォルダを作成できません。'
            );
        }

        $json = json_encode(
            $settings,
            JSON_UNESCAPED_UNICODE |
            JSON_UNESCAPED_SLASHES |
            JSON_PRETTY_PRINT
        );

        if ($json === false) {
            throw new RuntimeException(
                '設定データを作成できません。'
            );
        }

        if (
            file_put_contents(
                $path,
                $json,
                LOCK_EX
            ) === false
        ) {
            throw new RuntimeException(
                '設定を保存できません。'
            );
        }
    }

    /*
     * IP設定項目を確認
     */
    private static function validateIpSection(
        string $section
    ): void {
        if (
            !in_array(
                $section,
                ['allowed_ips', 'denied_ips'],
                true
            )
        ) {
            throw new RuntimeException(
                'IP設定項目が正しくありません。'
            );
        }
    }

    /*
     * 設定ファイルの保存場所
     */
    private static function settingsPath(): string
    {
        return BASE_PATH
            . '/storage/extensions/access-guard/settings.json';
    }
}