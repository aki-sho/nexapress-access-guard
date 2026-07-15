<?php

use app\Core\Router;
use NexaPressAccessGuard\AccessControl;
use NexaPressAccessGuard\SettingsController;

/*
 * NexaPress以外から直接実行された場合は終了
 */
if (
    !defined('BASE_PATH') ||
    !isset($router) ||
    !$router instanceof Router
) {
    return;
}

/*
 * 拡張機能のPHPファイルを読み込む
 */
$includeFiles = [
    __DIR__ . '/includes/Settings.php',
    __DIR__ . '/includes/SettingsController.php',
    __DIR__ . '/includes/IpRules.php',
    __DIR__ . '/includes/LoginUrl.php',
    __DIR__ . '/includes/LoginLock.php',
    __DIR__ . '/includes/FailOnce.php',
    __DIR__ . '/includes/AccessControl.php',
];

foreach ($includeFiles as $includeFile) {
    if (is_file($includeFile)) {
        require_once $includeFile;
    }
}

/*
 * 設定保存用URL
 */
$settingsBase =
    '/admin/extensions/access-guard/settings';

$router->post(
    $settingsBase . '/login-access',
    SettingsController::class . '@saveLoginAccess'
);

$router->post(
    $settingsBase . '/admin-access',
    SettingsController::class . '@saveAdminAccess'
);

$router->post(
    $settingsBase . '/login-url',
    SettingsController::class . '@saveLoginUrl'
);

$router->post(
    $settingsBase . '/login-lock',
    SettingsController::class . '@saveLoginLock'
);

$router->post(
    $settingsBase . '/fail-once',
    SettingsController::class . '@saveFailOnce'
);

/*
 * 許可IPの追加・削除
 */
$router->post(
    $settingsBase . '/allowed-ip/add',
    SettingsController::class . '@addAllowedIp'
);

$router->post(
    $settingsBase . '/allowed-ip/remove',
    SettingsController::class . '@removeAllowedIp'
);

/*
 * 拒否IPの追加・削除
 */
$router->post(
    $settingsBase . '/denied-ip/add',
    SettingsController::class . '@addDeniedIp'
);

$router->post(
    $settingsBase . '/denied-ip/remove',
    SettingsController::class . '@removeDeniedIp'
);

/*
 * アクセス保護処理を開始
 */
if (class_exists(AccessControl::class)) {
    AccessControl::boot($router);
}

/*
 * 設定画面用CSS
 */
if (function_exists('add_action')) {
    add_action('admin_head', function (): void {
        $requestPath = parse_url(
            $_SERVER['REQUEST_URI'] ?? '',
            PHP_URL_PATH
        );

        if (
            !is_string($requestPath) ||
            !str_contains(
                $requestPath,
                '/admin/extensions/access-guard/dashboard'
            )
        ) {
            return;
        }

        $cssFile =
            __DIR__ . '/assets/css/access-guard.css';

        if (!is_file($cssFile)) {
            return;
        }

        echo '<style>';
        readfile($cssFile);
        echo '</style>';
    });
}