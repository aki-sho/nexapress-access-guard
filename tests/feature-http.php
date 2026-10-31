<?php

/* tests/run.phpのHTTPハーネスから実行する。 */
require_once dirname(__DIR__) . '/includes/Totp.php';

function featureSignIn($client, string $username = 'admin'): array
{
    global $baseUrl;
    $page = request($client, $baseUrl, 'GET', '/secure-entry');
    return request($client, $baseUrl, 'POST', '/secure-entry', [
        '_csrf_token' => csrfToken($page['body']), 'username' => $username, 'password' => 'correct-password',
    ]);
}

function featureRecoveryCodes(string $body): array
{
    preg_match_all('/\b[a-f0-9]{5}(?:-[a-f0-9]{5}){3}\b/', $body, $matches);
    return $matches[0];
}

configureExtension($runtimeDirectory, true);
$mfaPath = '/admin/access-guard/two-factor';
$owner = newClient();
$oldSession = newClient();
assertSameValue(302, featureSignIn($owner)['status'], '二要素認証設定前の本人ログイン');
assertSameValue(302, featureSignIn($oldSession)['status'], '既存セッションを準備');
$page = request($owner, $baseUrl, 'GET', $mfaPath);
assertSameValue(200, $page['status'], '本人の二要素認証設定画面');
$token = csrfToken($page['body']);
$page = request($owner, $baseUrl, 'POST', $mfaPath, [
    '_csrf_token' => 'invalid', '_action' => 'begin', 'password' => 'correct-password',
]);
assertSameValue(419, $page['status'], '二要素認証の登録もCSRFを検証');
$page = request($owner, $baseUrl, 'POST', $mfaPath, [
    '_csrf_token' => $token, '_action' => 'begin', 'password' => 'incorrect',
]);
assertNotContainsText('otpauth://', $page['body'], '現在のパスワードが違えば秘密鍵を発行しない');
$page = request($owner, $baseUrl, 'POST', $mfaPath, [
    '_csrf_token' => $token, '_action' => 'begin', 'password' => 'correct-password',
]);
preg_match('/<code>([A-Z2-7]{32})<\/code>/', $page['body'], $matches);
$secret = $matches[1] ?? '';
assertSameValue(32, strlen($secret), '本人確認後にセットアップキーを表示');
assertContainsText('no-store', $page['headers'], '秘密鍵を表示する画面をキャッシュしない');
$page = request($owner, $baseUrl, 'POST', $mfaPath, [
    '_csrf_token' => $token, '_action' => 'enable', 'code' => \NexaPressAccessGuard\Totp::code($secret, time()),
]);
$codes = featureRecoveryCodes($page['body']);
assertSameValue(10, count($codes), 'コード確認後に復旧コードを10件表示');
assertContainsText('有効', $page['body'], '二要素認証の有効化');
$mfaStorage = $runtimeDirectory . '/storage/extensions/access-guard/two-factor.json';
assertNotContainsText($secret, file_get_contents($mfaStorage), 'セットアップキーを平文保存しない');
assertNotContainsText($codes[0], file_get_contents($mfaStorage), '復旧コードを平文保存しない');
$page = request($owner, $baseUrl, 'GET', $mfaPath);
assertSameValue([], featureRecoveryCodes($page['body']), '復旧コードは再表示しない');
$page = request($oldSession, $baseUrl, 'GET', '/admin');
assertSameValue(302, $page['status'], '有効化前のセッションは再ログインが必要');
curl_close($oldSession);

$client = newClient();
$page = featureSignIn($client);
assertSameValue(200, $page['status'], 'パスワードだけではログインを完了しない');
assertContainsText('name="_stage" value="two-factor"', $page['body'], '二段階目の認証画面を表示');
$challengeToken = csrfToken($page['body']);
$response = request($client, $baseUrl, 'GET', '/admin');
assertSameValue(302, $response['status'], '認証途中では管理画面に入れない');
$response = request($client, $baseUrl, 'POST', '/secure-entry', [
    '_csrf_token' => 'invalid', '_stage' => 'two-factor', 'code' => $codes[0],
]);
assertSameValue(419, $response['status'], '二段階目もCSRFを検証');
$response = request($client, $baseUrl, 'POST', '/secure-entry', [
    '_csrf_token' => $challengeToken, '_stage' => 'two-factor', 'code' => 'invalid',
]);
assertSameValue(200, $response['status'], '不正な二要素コードを拒否');
$response = request($client, $baseUrl, 'POST', '/secure-entry', [
    '_csrf_token' => $challengeToken, '_stage' => 'two-factor', 'code' => $codes[0],
]);
assertSameValue(302, $response['status'], '復旧コードを確認してログインを完了');
$response = request($client, $baseUrl, 'GET', '/admin');
assertSameValue(200, $response['status'], '二要素認証後は管理画面へ入れる');
request($client, $baseUrl, 'GET', '/admin/logout');
$response = featureSignIn($client);
$challengeToken = csrfToken($response['body']);
$response = request($client, $baseUrl, 'POST', '/secure-entry', [
    '_csrf_token' => $challengeToken, '_stage' => 'two-factor', 'code' => $codes[0],
]);
assertSameValue(200, $response['status'], '同じ復旧コードではログインできない');

// 登録で消費した時刻区間を過ぎた状態を用意し、待機なしでTOTP経路を検証する。
$data = json_decode(file_get_contents($mfaStorage), true);
$data[1]['last_counter'] = intdiv(time(), 30) - 2;
writeJson($mfaStorage, $data);
$response = request($client, $baseUrl, 'POST', '/secure-entry', [
    '_csrf_token' => $challengeToken, '_stage' => 'two-factor', 'code' => \NexaPressAccessGuard\Totp::code($secret, time()),
]);
assertSameValue(302, $response['status'], 'TOTPでも二段階認証を完了できる');

$response = request($owner, $baseUrl, 'POST', $mfaPath, [
    '_csrf_token' => $token, '_action' => 'regenerate', 'password' => 'incorrect', 'code' => $codes[1],
]);
assertSameValue([], featureRecoveryCodes($response['body']), '復旧コード再発行には現在のパスワードが必要');
$response = request($owner, $baseUrl, 'POST', $mfaPath, [
    '_csrf_token' => $token, '_action' => 'regenerate', 'password' => 'correct-password', 'code' => $codes[1],
]);
$newCodes = featureRecoveryCodes($response['body']);
assertSameValue(10, count($newCodes), '本人確認後の復旧コード再発行');
$response = request($client, $baseUrl, 'GET', '/admin');
assertSameValue(302, $response['status'], '再発行時は他のログイン済みセッションを無効化');

// セッションファイル内の認証期限を過去へ進める。
$expired = newClient();
$response = featureSignIn($expired);
$expiredToken = csrfToken($response['body']);
foreach (curl_getinfo($expired, CURLINFO_COOKIELIST) as $cookie) {
    $fields = explode("\t", $cookie);
    if (($fields[5] ?? '') === 'PHPSESSID' && preg_match('/^[a-zA-Z0-9,-]+$/D', $fields[6] ?? '')) {
        $sessionFile = $runtimeDirectory . '/sessions/sess_' . $fields[6];
        $session = file_get_contents($sessionFile);
        $session = preg_replace('/(s:7:"expires";i:)\d+;/', '${1}' . (time() - 1) . ';', $session);
        file_put_contents($sessionFile, $session);
    }
}
$response = request($expired, $baseUrl, 'POST', '/secure-entry', [
    '_csrf_token' => $expiredToken, '_stage' => 'two-factor', 'code' => $newCodes[0],
]);
assertSameValue(200, $response['status'], '期限切れの認証を完了しない');
assertContainsText('有効期限が切れました', $response['body'], '認証期限切れを表示');
curl_close($expired);

$blocked = newClient();
$response = featureSignIn($blocked);
$blockedToken = csrfToken($response['body']);
for ($attempt = 0; $attempt < 5; $attempt++) {
    $response = request($blocked, $baseUrl, 'POST', '/secure-entry', [
        '_csrf_token' => $blockedToken, '_stage' => 'two-factor', 'code' => 'invalid',
    ]);
}
assertContainsText('最初からログインしてください', $response['body'], '5回失敗した認証途中のセッションを破棄');
$response = featureSignIn($blocked);
$response = request($blocked, $baseUrl, 'POST', '/secure-entry', [
    '_csrf_token' => csrfToken($response['body']), '_stage' => 'two-factor', 'code' => $newCodes[0],
]);
assertSameValue(200, $response['status'], 'パスワード認証をやり直しても二要素ロックは維持');
assertContainsText('一時的に制限', $response['body'], '二要素認証のレート制限を表示');
curl_close($blocked);

// 管理者の解除操作を検証するため、5分のロック満了状態を用意する。
$data = json_decode(file_get_contents($mfaStorage), true);
$data[1]['locked_until'] = time() - 1;
writeJson($mfaStorage, $data);
$response = request($owner, $baseUrl, 'POST', $mfaPath, [
    '_csrf_token' => $token, '_action' => 'disable', 'password' => 'correct-password', 'code' => $newCodes[1],
]);
assertContainsText('未登録', $response['body'], '現在のパスワードと二要素を確認して解除');
curl_close($owner);
curl_close($client);

/* プロキシ経由のIP制限と、ヘッダー偽装の拒否。 */
configureExtension($runtimeDirectory, true, [
    'login_page_access' => ['enabled' => true],
    'allowed_ips' => ['203.0.113.10'],
    'trusted_proxy' => ['enabled' => true, 'proxies' => ['127.0.0.0/8', '10.0.0.0/8'], 'header' => 'x-forwarded-for'],
]);
$client = newClient();
curl_setopt($client, CURLOPT_HTTPHEADER, ['X-Forwarded-For: 203.0.113.10, 10.0.0.2']);
$response = request($client, $baseUrl, 'GET', '/secure-entry');
assertSameValue(200, $response['status'], '実利用者IPを許可IPに照合');
curl_setopt($client, CURLOPT_HTTPHEADER, ['X-Forwarded-For: 203.0.113.10, 198.51.100.99']);
$response = request($client, $baseUrl, 'GET', '/secure-entry');
assertSameValue(403, $response['status'], '偽装された左端の許可IPを採用しない');
curl_setopt($client, CURLOPT_HTTPHEADER, []);
$response = request($client, $baseUrl, 'GET', '/secure-entry');
assertSameValue(403, $response['status'], '信頼プロキシ経由のIP欠落は拒否');
configureExtension($runtimeDirectory, true, [
    'login_page_access' => ['enabled' => true], 'allowed_ips' => ['127.0.0.1'],
    'trusted_proxy' => ['enabled' => true, 'proxies' => ['192.0.2.1'], 'header' => 'x-forwarded-for'],
]);
curl_setopt($client, CURLOPT_HTTPHEADER, ['X-Forwarded-For: 198.51.100.99']);
$response = request($client, $baseUrl, 'GET', '/secure-entry');
assertSameValue(200, $response['status'], '信頼しない接続元では偽装ヘッダーを無視');
curl_close($client);

/* 新しい設定フォームと監査ログの閲覧。 */
configureExtension($runtimeDirectory, true);
$client = newClient();
featureSignIn($client);
$response = request($client, $baseUrl, 'GET', '/admin/extensions/access-guard/dashboard');
$token = csrfToken($response['body']);
assertContainsText('信頼済みプロキシ', $response['body'], '新機能を管理画面へ表示');
$response = request($client, $baseUrl, 'POST', '/admin/extensions/access-guard/settings/trusted-proxy', [
    '_csrf_token' => $token, 'enabled' => '1', 'proxies' => '127.0.0.1', 'header' => 'x-forwarded-for',
]);
assertSameValue(302, $response['status'], '接続IPが不明になる設定は保存せず戻る');
$settings = json_decode(file_get_contents($settingsPath), true);
assertSameValue(false, $settings['trusted_proxy']['enabled'] ?? false, '自己締め出しになるプロキシ有効化を防止');
$response = request($client, $baseUrl, 'POST', '/admin/extensions/access-guard/settings/monitoring', [
    '_csrf_token' => $token, 'retention_days' => '7', 'failure_threshold' => '5', 'email' => '',
]);
assertSameValue(302, $response['status'], '監査ログ設定を保存');
$settings = json_decode(file_get_contents($settingsPath), true);
assertSameValue(7, $settings['audit']['retention_days'], '監査ログの保持期間を保存');
$response = request($client, $baseUrl, 'POST', '/admin/extensions/access-guard/settings/monitoring', [
    '_csrf_token' => $token, 'enabled' => '1', 'retention_days' => '30', 'failure_threshold' => '5', 'email' => "bad\r\n@example.test",
]);
$settings = json_decode(file_get_contents($settingsPath), true);
assertSameValue(false, $settings['notifications']['enabled'], '不正な通知先は保存しない');
assertSameValue(7, $settings['audit']['retention_days'], '通知先不正時は保持期間も変更しない');
request($client, $baseUrl, 'POST', '/secure-entry', [
    '_csrf_token' => $token, 'username' => '<script>alert(1)</script>', 'password' => 'not-logged-password',
]);
$response = request($client, $baseUrl, 'GET', '/admin/extensions/access-guard/dashboard');
assertContainsText('&lt;script&gt;', $response['body'], '監査ログ内の入力値をエスケープする');
assertNotContainsText('<script>alert(1)</script>', $response['body'], '監査ログでスクリプトを実行させない');
$audit = file_get_contents($runtimeDirectory . '/storage/extensions/access-guard/audit.json');
assertNotContainsText('not-logged-password', $audit, 'ログにパスワードを記録しない');
assertContainsText('mfa_enabled', $audit, '二要素認証の登録を記録');
assertContainsText('recovery_used', $audit, '復旧コードの使用を記録');
assertContainsText('settings_changed', $audit, '保護設定の変更を記録');
curl_close($client);
