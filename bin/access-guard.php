<?php

/* Web経由では復旧処理を実行しない。 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

use NexaPressAccessGuard\AuditLog;
use NexaPressAccessGuard\IpRules;
use NexaPressAccessGuard\JsonStorage;
use NexaPressAccessGuard\LoginLock;
use NexaPressAccessGuard\Settings;
use NexaPressAccessGuard\TwoFactor;

$command = $argv[1] ?? 'help';
$options = [];

foreach (array_slice($argv, 2) as $argument) {
    if (!preg_match('/^--(base-path|ip|username|user-id|file)=(.+)$/D', $argument, $matches)) {
        fwrite(STDERR, "不正な引数です。helpを確認してください。\n");
        exit(1);
    }

    $options[$matches[1]] = $matches[2];
}

if ($command === 'help') {
    echo "php bin/access-guard.php COMMAND --base-path=本体の絶対パス\n"
        . "  status                  保護設定と二要素認証の登録IDを表示\n"
        . "  disable-access          ログイン・管理IP制限、変更URL、プロキシを無効化\n"
        . "  unlock --ip=IP --username=USER   指定したIP・アカウントのロック解除\n"
        . "  allow-ip --ip=IP         指定IPを許可し、拒否IPから除外\n"
        . "  disable-two-factor --user-id=ID  指定した本人の二要素認証を解除\n"
        . "  restore --file=settings|login-locks|two-factor  バックアップから復旧\n";
    exit(0);
}

$root = isset($options['base-path']) ? realpath($options['base-path']) : false;

if ($root === false || !is_dir($root . '/app') || !is_dir($root . '/storage')) {
    fwrite(STDERR, "--base-pathでNexaPress本体のapp・storageがあるフォルダを指定してください。\n");
    exit(1);
}

define('BASE_PATH', $root);

foreach (['JsonStorage', 'IpRules', 'Settings', 'LoginLock', 'TwoFactor', 'AuditLog', 'Notification'] as $class) {
    require dirname(__DIR__) . '/includes/' . $class . '.php';
}

try {
    $storage = BASE_PATH . '/storage/extensions/access-guard';

    if ($command === 'status') {
        $settings = Settings::all();
        echo json_encode([
            'login_page_access' => $settings['login_page_access']['enabled'],
            'admin_page_access' => $settings['admin_page_access']['enabled'],
            'login_url_changed' => $settings['login_url']['enabled'],
            'trusted_proxy' => $settings['trusted_proxy']['enabled'],
            'two_factor_user_ids' => array_keys(TwoFactor::all()),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
        exit(0);
    }

    if ($command === 'disable-access') {
        $settings = Settings::all();
        $settings['login_url']['enabled'] = false;
        $settings['trusted_proxy']['enabled'] = false;
        Settings::saveSections([
            'login_page_access' => ['enabled' => false],
            'admin_page_access' => ['enabled' => false],
            'login_url' => $settings['login_url'],
            'trusted_proxy' => $settings['trusted_proxy'],
        ]);
    } elseif ($command === 'allow-ip') {
        $ip = IpRules::normalize($options['ip'] ?? '');

        if ($ip === null) {
            throw new RuntimeException('--ipで正しいIPを指定してください。');
        }

        Settings::addIp('allowed_ips', $ip);
    } elseif ($command === 'unlock') {
        $ip = isset($options['ip']) ? IpRules::normalize($options['ip']) : null;
        $username = trim($options['username'] ?? '');

        if ((isset($options['ip']) && $ip === null) || ($ip === null && $username === '')) {
            throw new RuntimeException('--ipまたは--usernameを正しく指定してください。');
        }

        LoginLock::reset($ip, $username);
    } elseif ($command === 'disable-two-factor') {
        $id = filter_var($options['user-id'] ?? null, FILTER_VALIDATE_INT);

        if ($id === false || $id < 1) {
            throw new RuntimeException('--user-idで正のユーザーIDを指定してください。');
        }

        TwoFactor::reset($id);
    } elseif ($command === 'restore') {
        $validators = [
            'settings' => [Settings::class, 'validate'],
            'login-locks' => [LoginLock::class, 'validate'],
            'two-factor' => [TwoFactor::class, 'validate'],
        ];
        $file = $options['file'] ?? 'settings';

        if (!isset($validators[$file])) {
            throw new RuntimeException('復旧対象のファイルが正しくありません。');
        }

        JsonStorage::restore($storage . '/' . $file . '.json', $validators[$file]);
    } else {
        throw new RuntimeException('不明なコマンドです。helpを確認してください。');
    }

    AuditLog::record('cli_recovery', 'cli', ['source' => $command]);
    echo "完了: {$command}\n";
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . "\n");
    exit(1);
}
