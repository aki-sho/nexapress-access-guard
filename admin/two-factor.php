<?php
/* TwoFactorControllerから渡された本人の情報だけを表示する。 */
if (!isset($user, $csrfToken, $active)) {
    http_response_code(404);
    return;
}
?>
<div class="login-page"><div class="login-card">
    <h1>二要素認証</h1>
    <p><?= e($user['username']) ?>：<?= $active ? '有効' : '未登録' ?></p>
    <?php if ($error !== null): ?><p class="error-message"><?= e($error) ?></p><?php endif; ?>
    <?php if ($codes !== []): ?>
        <h2>復旧コード</h2>
        <p>この画面で一度だけ表示します。安全な場所へ保存してください。各コードは1回だけ使用できます。</p>
        <pre><?php foreach ($codes as $code): ?><?= e($code) . "\n" ?><?php endforeach; ?></pre>
    <?php endif; ?>
    <?php if (!$active && $pending !== null): ?>
        <p>認証アプリの「セットアップキーを入力」で、次のキーを登録してください。</p>
        <p><code><?= e($pending['secret']) ?></code></p>
        <?php $uri = 'otpauth://totp/' . rawurlencode('NexaPress:' . $user['username'])
            . '?secret=' . $pending['secret'] . '&issuer=NexaPress&algorithm=SHA1&digits=6&period=30'; ?>
        <p><a href="<?= e($uri) ?>">認証アプリで開く</a></p>
        <form action="<?= e($action) ?>" method="post">
            <input type="hidden" name="_csrf_token" value="<?= e($csrfToken) ?>">
            <input type="hidden" name="_action" value="enable">
            <label for="mfa-confirm">認証アプリの6桁の確認コード</label>
            <input id="mfa-confirm" name="code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required>
            <button class="button full" type="submit">二要素認証を有効にする</button>
        </form>
    <?php elseif (!$active): ?>
        <p>認証アプリで生成する確認コードを、ログイン時に追加で入力します。</p>
        <form action="<?= e($action) ?>" method="post">
            <input type="hidden" name="_csrf_token" value="<?= e($csrfToken) ?>">
            <input type="hidden" name="_action" value="begin">
            <label for="mfa-password">現在のパスワード</label>
            <input id="mfa-password" name="password" type="password" autocomplete="current-password" required>
            <button class="button full" type="submit">登録を開始する</button>
        </form>
    <?php else: ?>
        <p>確認コードは30秒ごとに更新されます。一度使用したコードは再使用できません。</p>
        <?php foreach (['regenerate' => '復旧コードを再発行する', 'disable' => '二要素認証を無効にする'] as $operation => $label): ?>
            <form action="<?= e($action) ?>" method="post">
                <input type="hidden" name="_csrf_token" value="<?= e($csrfToken) ?>">
                <input type="hidden" name="_action" value="<?= e($operation) ?>">
                <h2><?= e($label) ?></h2>
                <label>現在のパスワード<input name="password" type="password" autocomplete="current-password" required></label>
                <label>確認コードまたは未使用の復旧コード<input name="code" autocomplete="one-time-code" required></label>
                <button class="button full" type="submit"><?= e($label) ?></button>
            </form>
        <?php endforeach; ?>
    <?php endif; ?>
    <p><a href="<?= e(url('admin')) ?>">管理画面へ戻る</a></p>
</div></div>
