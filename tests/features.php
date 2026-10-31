<?php

namespace NexaPressAccessGuard {
    // メールは捕捉し、テストから外部へ送信しない。
    function mail(string $to, string $subject, string $body, string $headers): bool
    {
        $GLOBALS['feature_mail'][] = compact('to', 'subject', 'body', 'headers');
        return $GLOBALS['feature_mail_success'] ?? true;
    }
}

namespace {
    use NexaPressAccessGuard\AuditLog;
    use NexaPressAccessGuard\IpRules;
    use NexaPressAccessGuard\JsonStorage;
    use NexaPressAccessGuard\LoginLock;
    use NexaPressAccessGuard\SecretCipher;
    use NexaPressAccessGuard\Settings;
    use NexaPressAccessGuard\Totp;
    use NexaPressAccessGuard\TwoFactor;

    define('BASE_PATH', sys_get_temp_dir() . '/access-guard-features-' . bin2hex(random_bytes(6)));
    foreach (['JsonStorage', 'IpRules', 'Settings', 'LoginLock', 'Totp', 'SecretCipher', 'TwoFactor', 'Notification', 'AuditLog'] as $class) {
        require dirname(__DIR__) . '/includes/' . $class . '.php';
    }

    $assertions = 0;
    $GLOBALS['feature_mail'] = [];
    $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
    $storage = BASE_PATH . '/storage/extensions/access-guard';

    function checkFeature(bool $condition, string $message): void
    {
        global $assertions;
        $assertions++;

        if (!$condition) {
            throw new \RuntimeException($message);
        }
    }

    function featureCli(string $command, array $arguments = []): array
    {
        $process = proc_open(array_merge([
            PHP_BINARY, '-n', dirname(__DIR__) . '/bin/access-guard.php', $command, '--base-path=' . BASE_PATH,
        ], $arguments), [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($process), $output];
    }

    try {
        // RFC 6238 Appendix B のSHA-1テストベクトル。
        $rfcSecret = Totp::encode('12345678901234567890');
        foreach ([59 => '94287082', 1111111109 => '07081804', 1111111111 => '14050471',
            1234567890 => '89005924', 2000000000 => '69279037', 20000000000 => '65353130'] as $time => $code) {
            checkFeature(Totp::code($rfcSecret, $time, 8) === $code, 'RFC TOTP vector: ' . $time);
        }

        $now = time();
        $current = intdiv($now, 30);
        $code = Totp::code($rfcSecret, $now);
        checkFeature(Totp::counter($rfcSecret, $code, $now) === $current, '現在のTOTPを検証する');
        checkFeature(Totp::counter($rfcSecret, $code, $now, $current) === null, '同じ時刻のTOTPを再利用しない');
        checkFeature(Totp::counter($rfcSecret, Totp::code($rfcSecret, ($current - 1) * 30), $now) === $current - 1, '1区間の時刻ずれを許容する');
        checkFeature(Totp::counter($rfcSecret, Totp::code($rfcSecret, ($current - 3) * 30), $now) === null, '古いコードを拒否する');
        checkFeature(Totp::counter($rfcSecret, '12345x', $now) === null, '桁数・文字種を検証する');

        $secret = Totp::secret();
        checkFeature(strlen($secret) === 32, 'ランダムな160ビット秘密鍵を発行する');
        $codes = TwoFactor::enroll(1, $secret, Totp::code($secret, time()));
        checkFeature(count($codes) === 10 && count(array_unique($codes)) === 10, '異なる復旧コードを10件発行する');
        checkFeature(TwoFactor::enabled(1) && !TwoFactor::enabled(2), '二要素認証は本人のIDにだけ登録する');
        $stored = file_get_contents(TwoFactor::path());
        checkFeature(!str_contains($stored, $secret) && !str_contains($stored, $codes[0]), '秘密鍵と復旧コードを平文保存しない');
        checkFeature(!TwoFactor::verify(1, Totp::code($secret, time()))['valid'], '登録に使ったOTPはログインに再利用できない');
        $verified = TwoFactor::verify(1, $codes[0]);
        checkFeature($verified['valid'] && $verified['recovery'], '復旧コードで本人を確認できる');
        checkFeature(!TwoFactor::verify(1, $codes[0])['valid'], '復旧コードは1回だけ使用できる');

        $encrypted = TwoFactor::all()[1]['secret'];
        checkFeature(SecretCipher::decrypt($encrypted, 1) === $secret, '暗号化した秘密鍵を復号できる');
        $keyPath = $storage . '/two-factor.key';
        $savedKey = file_get_contents($keyPath);
        unlink($keyPath);
        try {
            SecretCipher::decrypt($encrypted, 1);
            checkFeature(false, '暗号鍵紛失時は停止する');
        } catch (\NexaPressAccessGuard\StorageException $exception) {
            checkFeature(!is_file($keyPath), '暗号鍵紛失時に別の鍵を自動生成しない');
        }
        file_put_contents($keyPath, '{}');
        try {
            SecretCipher::encrypt($secret, 1);
            checkFeature(false, '破損した暗号鍵を上書きしない');
        } catch (\NexaPressAccessGuard\StorageException $exception) {
            checkFeature(file_get_contents($keyPath) === '{}', '破損した暗号鍵を上書きしない');
        }
        file_put_contents($keyPath, $savedKey);
        try {
            SecretCipher::decrypt($encrypted, 2);
            checkFeature(false, '他人のIDで秘密鍵を復号しない');
        } catch (\NexaPressAccessGuard\StorageException $exception) {
            checkFeature(true, '他人のIDで秘密鍵を復号しない');
        }

        $version = TwoFactor::version(1);
        $new = TwoFactor::verify(1, $codes[1], 'regenerate');
        checkFeature($new['valid'] && count($new['codes']) === 10 && $version !== TwoFactor::version(1), '復旧コード再発行でセッション世代も変更する');
        checkFeature(!TwoFactor::verify(1, $codes[2])['valid'], '再発行前の復旧コードは使えない');
        checkFeature(TwoFactor::verify(1, $new['codes'][0], 'disable')['valid'] && !TwoFactor::enabled(1), '現在の要素を確認して解除する');

        $codes = TwoFactor::enroll(2, $secret, Totp::code($secret, time()));
        for ($attempt = 0; $attempt < 5; $attempt++) {
            TwoFactor::verify(2, 'invalid');
        }
        checkFeature(!TwoFactor::verify(2, $codes[0])['valid'], '5回失敗すると正しい復旧コードも一時ロックする');
        checkFeature(TwoFactor::all()[2]['locked_until'] >= time() + 298, '二要素認証のロックは5分間');

        $proxy = ['enabled' => true, 'proxies' => ['10.0.0.0/8', '2001:db8::/48'], 'header' => 'x-forwarded-for'];
        checkFeature(IpRules::normalizeNetwork('10.12.34.56/8') === '10.0.0.0/8', 'CIDRのネットワーク部を正規化する');
        checkFeature(IpRules::normalizeNetwork('0.0.0.0/0') === null, '全IPv4を信頼する設定を拒否する');
        checkFeature(IpRules::normalizeNetwork('::/0') === null, '全IPv6を信頼する設定を拒否する');
        checkFeature(IpRules::inNetwork('10.255.255.254', '10.0.0.0/8') && !IpRules::inNetwork('11.0.0.1', '10.0.0.0/8'), 'IPv4のCIDR境界');
        checkFeature(IpRules::inNetwork('2001:db8:0:1234::1', '2001:db8::/48') && !IpRules::inNetwork('2001:db8:1::1', '2001:db8::/48'), 'IPv6のCIDR境界');
        checkFeature(IpRules::resolve(['REMOTE_ADDR' => '192.0.2.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1'], $proxy) === '192.0.2.2', '信頼しない接続元の転送ヘッダーを無視する');
        checkFeature(IpRules::resolve(['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 10.0.0.3'], $proxy) === '198.51.100.1', '信頼する複数プロキシを右側からたどる');
        checkFeature(IpRules::resolve(['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '192.0.2.1, 198.51.100.99'], $proxy) === '198.51.100.99', '攻撃者が追加した左端のIPを採用しない');
        checkFeature(IpRules::resolve(['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => 'garbage'], $proxy) === '', '不正なヘッダーでプロキシ自身の許可IPに戻さない');
        checkFeature(IpRules::resolve(['REMOTE_ADDR' => '10.0.0.2'], $proxy) === '', '信頼プロキシのヘッダー欠落は判定不能にする');
        $proxy['header'] = 'cf-connecting-ip';
        checkFeature(IpRules::resolve(['REMOTE_ADDR' => '10.0.0.2', 'HTTP_CF_CONNECTING_IP' => '::ffff:192.0.2.9'], $proxy) === '192.0.2.9', '単一IPヘッダーも正規化する');
        checkFeature(IpRules::resolve(['REMOTE_ADDR' => '10.0.0.2', 'HTTP_CF_CONNECTING_IP' => '192.0.2.9, 192.0.2.10'], $proxy) === '', '単一IPヘッダーの複数IPを拒否する');

        Settings::saveSections(['notifications' => ['enabled' => true, 'email' => 'admin@example.test', 'failure_threshold' => 5]]);
        for ($attempt = 0; $attempt < 7; $attempt++) {
            AuditLog::record('login_failure', 'test-user', ['password' => 'do-not-log', 'code' => '123456']);
        }
        checkFeature(count($GLOBALS['feature_mail']) === 1, '失敗増加を1回だけ通知する');
        checkFeature($GLOBALS['feature_mail'][0]['to'] === 'admin@example.test', '設定した宛先へ通知する');
        checkFeature(!str_contains(file_get_contents(AuditLog::path()), 'do-not-log'), 'ログへ認証情報を書き込まない');
        AuditLog::record('test_input', "invalid-\xff");
        checkFeature(AuditLog::recent()[0]['event'] === 'test_input', '不正なUTF-8の入力でも監査ログを失わない');
        Settings::saveSection('login_page_access', ['enabled' => true]);
        Settings::saveSection('login_page_access', ['enabled' => false]);
        checkFeature(count($GLOBALS['feature_mail']) === 2, '保護設定の無効化を通知する');
        Settings::saveSection('notifications', ['enabled' => false, 'email' => 'admin@example.test', 'failure_threshold' => 5]);
        checkFeature(count($GLOBALS['feature_mail']) === 3, '通知そのものの無効化も元の宛先へ通知する');

        $row = AuditLog::recent()[0];
        $old = $row;
        $old['time'] = time() - 91 * 86400;
        $rows = [$old];
        for ($index = 0; $index < 2050; $index++) {
            $rows[] = $row;
        }
        file_put_contents(AuditLog::path(), json_encode($rows));
        AuditLog::record('login_success', 'bounded-log');
        checkFeature(count(json_decode(file_get_contents(AuditLog::path()), true)) === 2000, '監査ログは最大2000件');
        checkFeature(count(AuditLog::recent()) === 100, '管理画面には最新100件を返す');
        checkFeature(!in_array($old, json_decode(file_get_contents(AuditLog::path()), true), true), '保持期間を過ぎたログを削除する');

        mkdir(BASE_PATH . '/app');
        Settings::saveSections([
            'login_page_access' => ['enabled' => true], 'admin_page_access' => ['enabled' => true],
            'login_url' => ['enabled' => true, 'slug' => 'hidden-entry'],
        ]);
        checkFeature(featureCli('status')[0] === 0, 'CLIで保護状態を確認する');
        $badPath = featureCli('restore', ['--file=../../settings']);
        checkFeature($badPath[0] !== 0, 'CLIの復旧対象は固定ファイルに限定する');
        file_put_contents($storage . '/settings.json', '{');
        checkFeature(featureCli('restore', ['--file=settings'])[0] === 0, '設定破損をCLIで復旧する');
        checkFeature(Settings::get('admin_page_access')['enabled'], 'バックアップ内の保護設定を復元する');
        checkFeature(featureCli('disable-access')[0] === 0, 'CLIでアクセス制限を解除する');
        checkFeature(!Settings::get('admin_page_access')['enabled'] && !Settings::get('login_url')['enabled'], 'IP制限と標準URLを復旧する');
        Settings::addIp('denied_ips', '192.0.2.8');
        checkFeature(featureCli('allow-ip', ['--ip=::ffff:192.0.2.8'])[0] === 0 && IpRules::isAllowed('192.0.2.8') && !IpRules::isDenied('192.0.2.8'), 'CLIから自分のIPを許可・拒否解除する');
        Settings::saveSection('login_lock', ['enabled' => true, 'attempts' => 1, 'duration' => 30]);
        LoginLock::recordFailure('192.0.2.5', 'locked-user');
        checkFeature(LoginLock::isLocked('192.0.2.5', 'locked-user'), 'CLI解除前のロックを確認');
        checkFeature(featureCli('unlock', ['--ip=192.0.2.5', '--username=locked-user'])[0] === 0, 'CLIでIPとアカウントを解除する');
        checkFeature(!LoginLock::isLocked('192.0.2.5', 'locked-user'), '指定したロックが解除される');
        checkFeature(featureCli('disable-two-factor', ['--user-id=2'])[0] === 0 && !TwoFactor::enabled(2), 'CLIで紛失した二要素認証を復旧する');
        $events = array_column(AuditLog::recent(), 'event');
        checkFeature(in_array('cli_recovery', $events, true), 'CLI復旧を監査ログへ記録する');

        echo "PASS: {$assertions} feature assertions\n";
    } finally {
        if (is_dir(BASE_PATH)) {
            $root = realpath(BASE_PATH);
            if ($root === false || dirname($root) !== realpath(sys_get_temp_dir()) || !str_starts_with(basename($root), 'access-guard-features-')) {
                throw new \RuntimeException('一時フォルダの範囲を確認できません。');
            }
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($iterator as $file) {
                $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
            }
            rmdir($root);
        }
    }
}
