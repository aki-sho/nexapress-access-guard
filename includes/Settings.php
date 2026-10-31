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

            'trusted_proxy' => [
                'enabled' => false,
                'proxies' => [],
                'header' => 'x-forwarded-for',
            ],

            'audit' => ['retention_days' => 30],

            'notifications' => [
                'enabled' => false,
                'email' => '',
                'failure_threshold' => 10,
            ],
        ];
    }

    /*
     * 全設定を取得
     */
    public static function all(): array
    {
        return JsonStorage::read(
            self::settingsPath(),
            self::defaults(),
            [self::class, 'validate']
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
        self::saveSections([$section => $value]);
    }

    public static function saveSections(array $sections): void
    {
        $defaults = self::defaults();

        foreach ($sections as $section => $value) {
            if (!array_key_exists($section, $defaults)) {
                throw new RuntimeException('保存できない設定項目です。');
            }
        }

        self::update(static function (array &$settings) use ($sections): void {
            $settings = array_replace($settings, $sections);
        });
    }

    /*
     * IPを追加
     */
    public static function addIp(
        string $section,
        string $ip
    ): void {
        self::validateIpSection($section);
        $ip = IpRules::normalize($ip);

        if ($ip === null) {
            throw new RuntimeException('正しいIPアドレスを入力してください。');
        }

        self::update(static function (array &$settings) use ($section, $ip): void {
            $settings[$section][] = $ip;
            $opposite = $section === 'allowed_ips' ? 'denied_ips' : 'allowed_ips';
            $settings[$opposite] = array_values(array_diff($settings[$opposite], [$ip]));
        });
    }

    /*
     * IPを削除
     */
    public static function removeIp(
        string $section,
        string $ip
    ): void {
        self::validateIpSection($section);
        $ip = IpRules::normalize($ip);

        if ($ip === null) {
            throw new RuntimeException('正しいIPアドレスを入力してください。');
        }

        self::update(static function (array &$settings) use ($section, $ip): void {
            $settings[$section] = array_values(array_diff($settings[$section], [$ip]));
        });
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
     * 読み込みから保存までを同じ排他ロック内で処理する
     */
    private static function update(callable $callback): void
    {
        $before = null;
        JsonStorage::update(
            self::settingsPath(),
            self::defaults(),
            [self::class, 'validate'],
            static function (array &$settings) use ($callback, &$before): void {
                $before = $settings;
                $callback($settings);
            },
            true
        );

        if (class_exists(AuditLog::class)) {
            $after = self::all();

            foreach ($after as $section => $value) {
                if ($value !== $before[$section]) {
                    AuditLog::record('settings_changed', '', [
                        'section' => $section,
                        'disabled' => is_array($value) && isset($value['enabled']) && !$value['enabled'],
                    ], $before['notifications']);
                }
            }
        }
    }

    /* 部分的な初期値への復帰でも保護が解除されないよう検証する。 */
    public static function validate(array $settings): array
    {
        // 新機能だけを補完する。既存の保護設定が欠落した場合は従来どおり停止する。
        foreach (['trusted_proxy', 'audit', 'notifications'] as $section) {
            if (!array_key_exists($section, $settings)) {
                $settings[$section] = self::defaults()[$section];
            }
        }

        foreach (['login_page_access', 'admin_page_access', 'login_url', 'login_lock', 'fail_once'] as $section) {
            if (!isset($settings[$section]) || !is_array($settings[$section]) ||
                !isset($settings[$section]['enabled']) || !is_bool($settings[$section]['enabled'])) {
                throw new StorageException('保護設定の形式が正しくありません。');
            }
        }

        $slug = $settings['login_url']['slug'] ?? null;

        if (!is_string($slug) || !preg_match('/^[a-z0-9][a-z0-9_-]{2,63}$/', $slug) ||
            in_array($slug, ['admin', 'login', 'install', 'public'], true)) {
            throw new StorageException('ログインURLの設定が正しくありません。');
        }

        foreach ([['login_lock', 'attempts', 100], ['login_lock', 'duration', 1440], ['fail_once', 'count', 3]] as [$section, $key, $maximum]) {
            $value = $settings[$section][$key] ?? null;

            if (!is_int($value) || $value < 1 || $value > $maximum) {
                throw new StorageException('ログイン保護の設定値が正しくありません。');
            }
        }

        foreach (['allowed_ips', 'denied_ips'] as $section) {
            if (!isset($settings[$section]) || !is_array($settings[$section])) {
                throw new StorageException('IP設定の形式が正しくありません。');
            }

            $ips = [];

            foreach ($settings[$section] as $ip) {
                $normalized = is_string($ip) ? IpRules::normalize($ip) : null;

                if ($normalized === null) {
                    throw new StorageException('IP設定に不正なアドレスがあります。');
                }

                $ips[] = $normalized;
            }

            $ips = array_values(array_unique($ips));
            sort($ips);
            $settings[$section] = $ips;
        }

        $proxy = $settings['trusted_proxy'];

        if (!is_array($proxy) || !isset($proxy['enabled'], $proxy['proxies'], $proxy['header']) ||
            !is_bool($proxy['enabled']) || !is_array($proxy['proxies']) ||
            !in_array($proxy['header'], ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip'], true)) {
            throw new StorageException('信頼済みプロキシの設定が正しくありません。');
        }

        $proxies = [];

        foreach ($proxy['proxies'] as $network) {
            $normalized = is_string($network) ? IpRules::normalizeNetwork($network) : null;

            if ($normalized === null) {
                throw new StorageException('信頼済みプロキシのIP・CIDRが正しくありません。');
            }

            $proxies[] = $normalized;
        }

        if ($proxy['enabled'] && $proxies === []) {
            throw new StorageException('信頼するプロキシを登録してください。');
        }

        $settings['trusted_proxy']['proxies'] = array_values(array_unique($proxies));
        $audit = $settings['audit'];
        $notification = $settings['notifications'];

        if (!is_array($audit) || !isset($audit['retention_days']) ||
            !in_array($audit['retention_days'], [7, 30, 90], true)) {
            throw new StorageException('監査ログの保持期間が正しくありません。');
        }

        if (!is_array($notification) || !isset($notification['enabled'], $notification['email'], $notification['failure_threshold']) ||
            !is_bool($notification['enabled']) || !is_string($notification['email']) ||
            ($notification['email'] !== '' && filter_var($notification['email'], FILTER_VALIDATE_EMAIL) === false) ||
            ($notification['enabled'] && $notification['email'] === '') ||
            !in_array($notification['failure_threshold'], [5, 10, 20, 50], true)) {
            throw new StorageException('異常通知の設定が正しくありません。');
        }

        return $settings;
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
