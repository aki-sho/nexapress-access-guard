<?php
if (!isset($settings, $csrfToken)) {
    http_response_code(404);
    return;
}

$proxy = $settings['trusted_proxy'];
$monitoring = $settings['notifications'];
$logs = [];
$logError = false;

try {
    $logs = \NexaPressAccessGuard\AuditLog::recent();
} catch (\NexaPressAccessGuard\StorageException $exception) {
    $logError = true;
}

$labels = [
    'login_success' => 'ログイン成功', 'login_failure' => 'ログイン失敗',
    'login_locked' => 'ログインロック', 'logout' => 'ログアウト',
    'access_denied' => 'アクセス拒否', 'settings_changed' => '設定変更',
    'mfa_enabled' => '二要素認証を登録', 'mfa_disabled' => '二要素認証を解除',
    'mfa_failure' => '二要素認証に失敗', 'mfa_management_failure' => '二要素認証の設定確認に失敗',
    'recovery_used' => '復旧コードを使用', 'recovery_regenerated' => '復旧コードを再発行',
    'cli_recovery' => 'サーバーから復旧', 'notification_failed' => '通知メール送信失敗',
];
?>
<div class="access-guard-grid">
    <section class="access-guard-card">
        <h2>二要素認証</h2>
        <p>認証アプリの確認コードをログイン時に追加します。自分のアカウントに登録し、復旧コードを安全に保管してください。</p>
        <a class="button" href="<?= e(url('admin/access-guard/two-factor')) ?>">自分の二要素認証を設定</a>
    </section>
    <section class="access-guard-card">
        <h2>信頼済みプロキシ</h2>
        <p>CDNやリバースプロキシを使用している場合に設定します。管理するプロキシのIP・CIDRだけを登録してください。</p>
        <form action="<?= e(url('admin/extensions/access-guard/settings/trusted-proxy')) ?>" method="post">
            <input type="hidden" name="_csrf_token" value="<?= e($csrfToken) ?>">
            <label class="access-guard-switch-row"><input type="checkbox" name="enabled" value="1" <?= $proxy['enabled'] ? 'checked' : '' ?>>利用者IPを転送情報から判定する</label>
            <div class="access-guard-field">
                <label for="proxy-list">信頼するプロキシ（1行に1件、IPv4・IPv6・CIDR）</label>
                <textarea id="proxy-list" name="proxies" rows="4" placeholder="192.0.2.10&#10;2001:db8::/48"><?= e(implode("\n", $proxy['proxies'])) ?></textarea>
            </div>
            <div class="access-guard-field">
                <label for="proxy-header">プロキシが設定するヘッダー</label>
                <select id="proxy-header" name="header">
                    <?php foreach (['x-forwarded-for' => 'X-Forwarded-For', 'x-real-ip' => 'X-Real-IP', 'cf-connecting-ip' => 'CF-Connecting-IP'] as $value => $label): ?>
                        <option value="<?= e($value) ?>" <?= $proxy['header'] === $value ? 'selected' : '' ?>><?= e($label) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <p>プロキシ側で外部からの転送情報を適切に更新してください。IP制限中は、切り替え後の利用者IPも先に許可IPへ登録してください。</p>
            <button class="button" type="submit">この設定を保存</button>
        </form>
    </section>
    <section class="access-guard-card">
        <h2>監査ログ・異常通知</h2>
        <p>ログインと保護設定の変更を記録します。短時間の認証失敗増加や保護設定の無効化をメールで通知できます。</p>
        <form action="<?= e(url('admin/extensions/access-guard/settings/monitoring')) ?>" method="post">
            <input type="hidden" name="_csrf_token" value="<?= e($csrfToken) ?>">
            <div class="access-guard-field">
                <label for="audit-retention">ログ保持期間（最大2,000件）</label>
                <select id="audit-retention" name="retention_days">
                    <?php foreach ([7, 30, 90] as $days): ?><option value="<?= $days ?>" <?= $settings['audit']['retention_days'] === $days ? 'selected' : '' ?>><?= $days ?>日</option><?php endforeach; ?>
                </select>
            </div>
            <label class="access-guard-switch-row"><input type="checkbox" name="enabled" value="1" <?= $monitoring['enabled'] ? 'checked' : '' ?>>メールで異常を通知する</label>
            <div class="access-guard-field"><label for="alert-email">通知先メールアドレス</label><input id="alert-email" type="email" name="email" value="<?= e($monitoring['email']) ?>"></div>
            <div class="access-guard-field">
                <label for="alert-threshold">5分以内の認証失敗が次の回数に達したら通知</label>
                <select id="alert-threshold" name="failure_threshold">
                    <?php foreach ([5, 10, 20, 50] as $count): ?><option value="<?= $count ?>" <?= $monitoring['failure_threshold'] === $count ? 'selected' : '' ?>><?= $count ?>回</option><?php endforeach; ?>
                </select>
            </div>
            <p>サーバーのPHPメール送信設定が必要です。同じ種類の通知は5分間に1回までに制限します。</p>
            <button class="button" type="submit">この設定を保存</button>
        </form>
    </section>
</div>
<section class="access-guard-card">
    <h2>最近の監査ログ</h2>
    <p>最新100件を表示します。日時はUTCです。</p>
    <?php if ($logError): ?>
        <p class="error-message">監査ログを読み込めません。サーバー上の保存データを確認してください。</p>
    <?php elseif ($logs === []): ?>
        <p>ログはまだありません。</p>
    <?php else: ?>
        <div class="access-guard-table-scroll"><table class="access-guard-audit-table">
            <thead><tr><th>日時（UTC）</th><th>操作</th><th>ユーザー</th><th>接続元IP</th><th>対象</th></tr></thead>
            <tbody><?php foreach ($logs as $entry): ?><tr>
                <td><?= e(gmdate('Y-m-d H:i:s', $entry['time'])) ?></td>
                <td><?= e($labels[$entry['event']] ?? $entry['event']) ?></td>
                <td><?= e($entry['username']) ?></td><td><?= e($entry['ip']) ?></td>
                <td><?= e((string)($entry['details']['section'] ?? $entry['details']['source'] ?? $entry['details']['reason'] ?? '')) ?></td>
            </tr><?php endforeach; ?></tbody>
        </table></div>
    <?php endif; ?>
</section>
