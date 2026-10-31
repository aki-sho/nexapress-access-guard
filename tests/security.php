<?php

use NexaPressAccessGuard\IpRules;
use NexaPressAccessGuard\LoginLock;
use NexaPressAccessGuard\Settings;
use NexaPressAccessGuard\StorageException;

define('BASE_PATH', sys_get_temp_dir() . '/access-guard-security-' . bin2hex(random_bytes(6)));
require dirname(__DIR__) . '/includes/JsonStorage.php';
require dirname(__DIR__) . '/includes/IpRules.php';
require dirname(__DIR__) . '/includes/Settings.php';
require dirname(__DIR__) . '/includes/LoginLock.php';

$assertions = 0;
$storage = BASE_PATH . '/storage/extensions/access-guard';
$settingsPath = $storage . '/settings.json';
$locksPath = $storage . '/login-locks.json';

function expect(bool $condition, string $message): void
{
    global $assertions;
    $assertions++;

    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function rejects(callable $callback, string $message): void
{
    try {
        $callback();
    } catch (StorageException $exception) {
        expect(true, $message);
        return;
    }

    expect(false, $message);
}

function writeState(string $path, array $data): void
{
    file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR));
}

function clearLocks(): void
{
    global $locksPath;

    foreach ([$locksPath, $locksPath . '.bak'] as $path) {
        if (is_file($path)) {
            unlink($path);
        }
    }
}

function runWorkers(string $mode): void
{
    $workers = [];

    for ($worker = 0; $worker < 4; $worker++) {
        $process = proc_open(
            [PHP_BINARY, '-n', __DIR__ . '/storage-worker.php', BASE_PATH, $mode, (string)$worker],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );

        if (!is_resource($process)) {
            throw new RuntimeException('ワーカーを起動できません。');
        }

        fclose($pipes[0]);
        $workers[] = [$process, $pipes];
    }

    foreach ($workers as [$process, $pipes]) {
        $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        expect(proc_close($process) === 0, '並行書き込みの完了: ' . $output);
    }
}

try {
    expect(Settings::all() === Settings::defaults(), '初回のみ初期設定を使用する');
    Settings::saveSection('admin_page_access', ['enabled' => true]);
    expect(is_file($settingsPath . '.bak'), '設定のバックアップを作成する');
    expect(file_get_contents($settingsPath) === file_get_contents($settingsPath . '.bak'), 'バックアップに保存設定を保持する');
    $saved = file_get_contents($settingsPath);

    foreach (['{', '', '{}', '[]', 'null'] as $invalid) {
        file_put_contents($settingsPath, $invalid);
        rejects(static fn() => Settings::all(), '不正な設定を初期値に戻さない: ' . $invalid);
    }

    file_put_contents($settingsPath, $saved);
    $invalid = Settings::all();
    $invalid['admin_page_access']['enabled'] = 'false';
    writeState($settingsPath, $invalid);
    rejects(static fn() => Settings::all(), '真偽値の型不正を拒否する');
    unlink($settingsPath);
    rejects(static fn() => Settings::all(), 'バックアップがある設定の消失を初回扱いにしない');
    file_put_contents($settingsPath, $saved);
    expect(Settings::get('admin_page_access')['enabled'], '復旧後も保護設定を維持する');

    // 保存先の障害時に、元の保護設定を途中まで上書きしない。
    unlink($settingsPath . '.bak');
    mkdir($settingsPath . '.bak');
    rejects(static fn() => Settings::saveSection('admin_page_access', ['enabled' => false]), '保存失敗を検知する');
    expect(Settings::get('admin_page_access')['enabled'], '保存失敗時は既存の保護を維持する');
    rmdir($settingsPath . '.bak');
    file_put_contents($settingsPath . '.bak', $saved);

    $long = '2001:0DB8:0000:0000:0000:0000:0000:0001';
    $short = '2001:db8::1';
    Settings::addIp('denied_ips', $long);
    expect(IpRules::isDenied($short), 'IPv6の省略形でも拒否する');
    Settings::addIp('denied_ips', $short);
    expect(count(Settings::get('denied_ips')) === 1, 'IPv6の別表記を重複登録しない');
    Settings::removeIp('denied_ips', $long);
    expect(!IpRules::isDenied($short), '別表記から登録IPを削除できる');
    Settings::addIp('allowed_ips', $long);
    expect(IpRules::isAllowed($short), 'IPv6の別表記を許可IPに照合する');
    Settings::addIp('denied_ips', $short);
    expect(!IpRules::isAllowed($long) && IpRules::isDenied($long), '許可・拒否間の移動も正規化する');
    Settings::addIp('denied_ips', '::ffff:192.0.2.1');
    expect(IpRules::isDenied('192.0.2.1'), 'IPv4射影アドレスも同じIPとして拒否する');
    expect(IpRules::normalize('not-an-ip') === null, '不正なIPを拒否する');

    // 手動編集済みの旧設定も、読み込み時に正規化できる。
    $legacy = Settings::all();
    $legacy['denied_ips'] = [$long];
    writeState($settingsPath, $legacy);
    expect(IpRules::isDenied($short), '旧版の完全表記IPも読み込める');
    $_SERVER['REMOTE_ADDR'] = '::ffff:127.0.0.1';
    expect(IpRules::currentIp() === '127.0.0.1', '接続元IPも正規化する');

    Settings::saveSection('login_lock', ['enabled' => true, 'attempts' => 3, 'duration' => 30]);
    expect(!LoginLock::recordFailure('192.0.2.10', 'Admin'), '分散攻撃の1回目');
    expect(!LoginLock::recordFailure('192.0.2.11', 'admin'), '分散攻撃の2回目');
    expect(LoginLock::recordFailure('192.0.2.12', 'ADMIN'), 'IPを変えてもアカウントが上限に達する');
    expect(LoginLock::isLocked('192.0.2.99', 'admin'), '新しいIPからも同じアカウントを拒否する');
    expect(!LoginLock::isLocked('192.0.2.99', 'other'), '無関係なアカウントはロックしない');
    expect(LoginLock::remainingMinutes('192.0.2.99', 'admin') > 0, 'アカウントの残りロック時間を取得できる');
    expect(!LoginLock::clear('192.0.2.99', 'admin'), '成功処理でもロック中のアカウントを解除しない');

    clearLocks();
    LoginLock::recordFailure('192.0.2.20', 'first');
    LoginLock::recordFailure('192.0.2.20', 'second');
    expect(LoginLock::recordFailure('192.0.2.20', 'third'), 'ユーザー名を変えてもIPでロックする');
    expect(LoginLock::isLocked('192.0.2.20', 'fourth'), '同じIPの別アカウントも制限する');

    clearLocks();
    Settings::saveSection('login_lock', ['enabled' => true, 'attempts' => 10, 'duration' => 30]);
    LoginLock::recordFailure('192.0.2.30', 'target');
    expect(LoginLock::clear('192.0.2.30', 'target'), '待機前なら正しいログインを完了できる');
    $data = json_decode(file_get_contents($locksPath), true);
    expect($data['192.0.2.30']['count'] === 1 && count($data) === 1, '成功時もIP全体の失敗履歴は消さない');
    LoginLock::recordFailure('192.0.2.30', 'other');
    expect(LoginLock::retryAfterSeconds('192.0.2.30', 'other') > 0, '連続失敗で待機時間を設ける');

    $data = json_decode(file_get_contents($locksPath), true);
    foreach ($data as &$entry) {
        $entry['updated_at'] = time() - 901;
        $entry['next_attempt_at'] = time() - 1;
    }
    unset($entry);
    writeState($locksPath, $data);
    LoginLock::recordFailure('192.0.2.30', 'other');
    expect(LoginLock::retryAfterSeconds('192.0.2.30', 'other') === 0, '観測期間を過ぎた失敗履歴をリセットする');

    clearLocks();
    writeState($locksPath, [$long => ['count' => 0, 'locked_until' => time() + 600, 'updated_at' => time()]]);
    expect(LoginLock::isLocked($short), '旧版のIPv6ロックを引き継ぐ');
    file_put_contents($locksPath, '{');
    rejects(static fn() => LoginLock::isLocked($short), 'ロックファイル破損時も解除しない');
    clearLocks();

    Settings::saveSection('allowed_ips', []);
    runWorkers('settings');
    expect(count(Settings::get('allowed_ips')) === 32, '並行保存でIP登録を失わない');
    expect(Settings::get('admin_page_access')['enabled'], '並行保存で別セクションの設定を失わない');

    Settings::saveSection('login_lock', ['enabled' => true, 'attempts' => 100, 'duration' => 30]);
    runWorkers('locks');
    $data = json_decode(file_get_contents($locksPath), true);
    $account = 'account:' . hash('sha256', 'parallel-account');
    expect($data[$account]['count'] === 32, '並行失敗をアカウント単位で漏れなく累積する');
    expect(count(glob($storage . '/.access-guard-*')) === 0, '保存後に一時ファイルを残さない');

    echo "PASS: {$assertions} security assertions\n";
} finally {
    // このテストが生成した単一の一時ディレクトリのみを削除する。
    if (is_dir(BASE_PATH)) {
        $resolvedRoot = realpath(BASE_PATH);

        if ($resolvedRoot === false || dirname($resolvedRoot) !== realpath(sys_get_temp_dir()) ||
            !str_starts_with(basename($resolvedRoot), 'access-guard-security-')) {
            throw new RuntimeException('テスト用一時フォルダの範囲を確認できません。');
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($resolvedRoot, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }

        rmdir(BASE_PATH);
    }
}
