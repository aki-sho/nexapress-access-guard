<?php

namespace NexaPressAccessGuard;

use app\Core\Auth;
use app\Core\Router;

/*
 * ログインページ・管理ページのアクセス制御
 */
class AccessControl
{
    /*
     * アクセス制御を開始
     */
    public static function boot(Router $router): void
    {
        try {
            self::enforce($router);
        } catch (StorageException $exception) {
            JsonStorage::unavailable();
        }
    }

    private static function enforce(Router $router): void
    {
        /*
         * ログイン用ルートを登録
         */
        LoginUrl::register($router);

        $path = self::requestPath();
        $ip = IpRules::currentIp();

        if (!self::isProtectedPath($path)) {
            return;
        }

        if ($ip === '') {
            AuditLog::record('access_denied', '', ['reason' => 'invalid_client_ip']);
            self::deny();
        }

        /*
         * 拒否IPは管理関連ページへアクセス不可
         */
        if (IpRules::isDenied($ip)) {
            AuditLog::record('access_denied', '', ['reason' => 'denied_ip']);
            self::deny();
        }

        /*
         * ログインページのアクセス制限
         */
        if (self::isLoginPath($path)) {
            self::checkLoginPageAccess($ip);
            return;
        }

        /*
         * 管理ページのアクセス制限
         */
        if (self::isAdminPath($path)) {
            self::checkAdminPageAccess($ip);
            self::checkSecondFactorSession();
            self::redirectGuestToLogin();
        }
    }

    private static function checkSecondFactorSession(): void
    {
        if (!Auth::check()) {
            return;
        }

        $user = Auth::user();
        $version = TwoFactor::version((int)($user['id'] ?? 0));

        if ($version !== null && !hash_equals($version, (string)($_SESSION['access_guard_mfa_verified'] ?? ''))) {
            Auth::logout();
            unset($_SESSION['access_guard_mfa_verified'], $_SESSION['access_guard_pending_login']);
            redirect_to(ltrim(LoginUrl::path(), '/'));
        }
    }

    /*
     * ログインURL変更中の未ログインユーザーを誘導
     */
    private static function redirectGuestToLogin(): void
    {
        $setting = Settings::get(
            'login_url',
            []
        );

        if (
            empty($setting['enabled']) ||
            Auth::check()
        ) {
            return;
        }

        redirect_to(
            ltrim(
                LoginUrl::path(),
                '/'
            )
        );
    }

    /*
     * ログインページアクセス制限
     */
    private static function checkLoginPageAccess(
        string $ip
    ): void {
        $setting = Settings::get(
            'login_page_access',
            []
        );

        if (empty($setting['enabled'])) {
            return;
        }

        if (!IpRules::isAllowed($ip)) {
            AuditLog::record('access_denied', '', ['reason' => 'login_allowlist']);
            self::deny();
        }
    }

    /*
     * 管理ページアクセス制限
     */
    private static function checkAdminPageAccess(
        string $ip
    ): void {
        $setting = Settings::get(
            'admin_page_access',
            []
        );

        if (empty($setting['enabled'])) {
            return;
        }

        if (!IpRules::isAllowed($ip)) {
            AuditLog::record('access_denied', '', ['reason' => 'admin_allowlist']);
            self::deny();
        }
    }

    /*
     * 管理関連のパスか確認
     */
    private static function isProtectedPath(
        string $path
    ): bool {
        return self::isLoginPath($path) ||
            self::isAdminPath($path);
    }

    /*
     * ログインページか確認
     */
    private static function isLoginPath(
        string $path
    ): bool {
        return in_array(
            $path,
            [
                '/admin/login',
                LoginUrl::path(),
            ],
            true
        );
    }

    /*
     * 管理ページか確認
     */
    private static function isAdminPath(
        string $path
    ): bool {
        return $path === '/admin' ||
            str_starts_with(
                $path,
                '/admin/'
            );
    }

    /*
     * 現在のリクエストパスを取得
     */
    private static function requestPath(): string
    {
        $path = parse_url(
            $_SERVER['REQUEST_URI'] ?? '/',
            PHP_URL_PATH
        );

        if (!is_string($path)) {
            return '/';
        }

        $baseUrl = defined('BASE_URL')
            ? rtrim(BASE_URL, '/')
            : '';

        if (
            $baseUrl !== '' &&
            str_starts_with($path, $baseUrl)
        ) {
            $path = substr(
                $path,
                strlen($baseUrl)
            );
        }

        $path = '/' . trim($path, '/');

        return $path === ''
            ? '/'
            : $path;
    }

    /*
     * アクセス拒否
     */
    private static function deny(): void
    {
        http_response_code(403);

        header(
            'Cache-Control: no-store, no-cache, must-revalidate'
        );

        exit('このページへのアクセスは許可されていません。');
    }
}
