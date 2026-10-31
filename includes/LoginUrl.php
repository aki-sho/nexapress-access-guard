<?php

namespace NexaPressAccessGuard;

use app\Core\Auth;
use app\Core\Controller;
use app\Core\Csrf;
use app\Core\Router;
use app\Models\User;

/*
 * ログインページとログイン処理
 */
class LoginUrl extends Controller
{
    /*
     * ログイン用ルートを登録
     */
    public static function register(
        Router $router
    ): void {
        $setting = Settings::get(
            'login_url',
            []
        );

        $enabled =
            !empty($setting['enabled']);

        if ($enabled) {
            /*
             * 変更後のログインURL
             */
            $router->get(
                self::path(),
                self::class . '@show'
            );

            $router->post(
                self::path(),
                self::class . '@authenticate'
            );

            /*
             * 元のログインURLを無効化
             */
            $router->get(
                '/admin/login',
                self::class . '@notFound'
            );

            $router->post(
                '/admin/login',
                self::class . '@notFound'
            );
        } else {
            /*
             * 標準ログインURLを使用
             */
            $router->get(
                '/admin/login',
                self::class . '@show'
            );

            $router->post(
                '/admin/login',
                self::class . '@authenticate'
            );
        }

        /*
         * ログアウト後も現在のログインURLへ戻す
         */
        $router->get(
            '/admin/logout',
            self::class . '@logout'
        );
    }

    /*
     * 現在使用するログインパス
     */
    public static function path(): string
    {
        $setting = Settings::get(
            'login_url',
            []
        );

        if (empty($setting['enabled'])) {
            return '/admin/login';
        }

        $slug = trim(
            (string)(
                $setting['slug'] ?? 'secure-login'
            ),
            '/'
        );

        return '/' . $slug;
    }

    /*
     * ログイン画面
     */
    public function show(): void
    {
        if (Auth::check()) {
            redirect_to('admin');
        }

        if ($this->pendingLogin() !== null) {
            $this->renderChallenge();
            return;
        }

        $this->renderLogin();
    }

    /*
     * ログイン処理
     */
    public function authenticate(): void
    {
        try {
            $this->authenticateRequest();
        } catch (StorageException $exception) {
            JsonStorage::unavailable();
        }
    }

    private function authenticateRequest(): void
    {
        Csrf::requireValid(
            $_POST['_csrf_token'] ?? null
        );

        if (($_POST['_stage'] ?? '') === 'two-factor') {
            $this->authenticateSecondFactor();
            return;
        }

        unset($_SESSION['access_guard_pending_login']);

        $ip = IpRules::currentIp();
        $username = trim((string)($_POST['username'] ?? ''));

        /*
         * ロック中は認証処理を行わない
         */
        if ($this->rejectLocked($ip, $username)) {
            return;
        }

        $password =
            (string)($_POST['password'] ?? '');

        if ($username === '' || $password === '') {
            $this->renderLogin(
                'ユーザー名とパスワードを入力してください。',
                $username
            );

            return;
        }

        $user = User::findByUsername($username);

        if (
            !$user ||
            !password_verify(
                $password,
                $user['password_hash']
            )
        ) {
            $locked =
                LoginLock::recordFailure($ip, $username);
            AuditLog::record('login_failure', $username);

            if ($locked) {
                AuditLog::record('login_locked', $username);
            }

            $message = $locked
                ? 'ログイン失敗回数が上限に達したため、'
                    . '一時的にロックしました。'
                : 'ログイン情報が正しくありません。';

            $this->renderLogin(
                $message,
                $username
            );

            return;
        }

        /*
         * 正しい認証情報でも指定回数だけ失敗させる
         */
        if (
            FailOnce::shouldReject(
                $ip,
                $username
            )
        ) {
            $this->renderLogin(
                'ログイン情報が正しくありません。',
                $username
            );

            return;
        }

        if (TwoFactor::enabled((int)$user['id'])) {
            unset($_SESSION['user'], $_SESSION['access_guard_mfa_verified']);
            session_regenerate_id(true);
            Csrf::regenerate();
            $_SESSION['access_guard_pending_login'] = [
                'id' => (int)$user['id'],
                'username' => $user['username'],
                'password' => hash('sha256', $user['password_hash']),
                'ip' => $ip,
                'expires' => time() + 300,
                'attempts' => 0,
            ];
            $this->renderChallenge();
            return;
        }

        $this->completeLogin($user, $ip);
    }

    private function completeLogin(array $user, string $ip, ?string $mfaVersion = null): void
    {
        $username = $user['username'];
        // パスワード検証中に別リクエストでロックされた場合も拒否する。
        if ($this->rejectLocked($ip, $username)) {
            return;
        }

        if (!LoginLock::clear($ip, $username)) {
            $this->renderLogin('ログインが一時的にロックされています。時間をおいて再度お試しください。');
            return;
        }

        FailOnce::clear(
            $ip,
            $username
        );

        session_regenerate_id(true);

        Auth::login($user);

        $_SESSION['access_guard_mfa_verified'] = $mfaVersion;
        unset($_SESSION['access_guard_pending_login']);
        AuditLog::record('login_success', $username);

        Csrf::regenerate();

        redirect_to('admin');
    }

    private function pendingLogin(): ?array
    {
        $pending = $_SESSION['access_guard_pending_login'] ?? null;

        if (!is_array($pending) || ($pending['expires'] ?? 0) <= time() ||
            ($pending['attempts'] ?? 5) >= 5 || ($pending['ip'] ?? '') !== IpRules::currentIp()) {
            unset($_SESSION['access_guard_pending_login']);
            return null;
        }

        return $pending;
    }

    private function authenticateSecondFactor(): void
    {
        $pending = $this->pendingLogin();

        if ($pending === null) {
            $this->renderLogin('認証の有効期限が切れました。最初からログインしてください。');
            return;
        }

        $user = User::findByUsername($pending['username']);

        if (!$user || (int)$user['id'] !== $pending['id'] ||
            !hash_equals($pending['password'], hash('sha256', $user['password_hash']))) {
            unset($_SESSION['access_guard_pending_login']);
            $this->renderLogin('認証情報が変更されました。最初からログインしてください。');
            return;
        }

        if ($this->rejectLocked($pending['ip'], $pending['username'])) {
            return;
        }

        $_SESSION['access_guard_pending_login']['attempts']++;
        $result = TwoFactor::verify($pending['id'], (string)($_POST['code'] ?? ''));

        if (!$result['valid']) {
            AuditLog::record('mfa_failure', $pending['username']);
            LoginLock::recordFailure($pending['ip'], $pending['username']);

            if ($this->pendingLogin() === null) {
                $this->renderLogin('認証に失敗しました。最初からログインしてください。');
            } else {
                $this->renderChallenge('確認コードが正しくないか、一時的に制限されています。');
            }

            return;
        }

        if ($result['recovery']) {
            AuditLog::record('recovery_used', $pending['username']);
        }

        $this->completeLogin($user, $pending['ip'], $result['version']);
    }

    private function renderChallenge(?string $error = null): void
    {
        header('Cache-Control: no-store');
        $title = '二要素認証';
        $action = url(ltrim(self::path(), '/'));
        $csrfToken = Csrf::token();
        ob_start();
        ?>
        <div class="login-page"><div class="login-card">
            <h1>二要素認証</h1>
            <p>認証アプリの6桁の確認コード、または未使用の復旧コードを入力してください。</p>
            <?php if ($error !== null): ?><p class="error-message"><?= e($error) ?></p><?php endif; ?>
            <form action="<?= e($action) ?>" method="post">
                <input type="hidden" name="_csrf_token" value="<?= e($csrfToken) ?>">
                <input type="hidden" name="_stage" value="two-factor">
                <label for="mfa-code">確認コード・復旧コード</label>
                <input id="mfa-code" name="code" autocomplete="one-time-code" required autofocus>
                <button class="button full" type="submit">確認してログイン</button>
            </form>
        </div></div>
        <?php
        $content = ob_get_clean();
        require BASE_PATH . '/app/Views/admin/login-layout.php';
    }

    private function rejectLocked(string $ip, string $username): bool
    {
        $seconds = LoginLock::retryAfterSeconds($ip, $username);

        if ($seconds <= 0) {
            return false;
        }

        header('Retry-After: ' . $seconds);
        $this->renderLogin(
            'ログインが一時的にロックされています。約'
            . $seconds
            . '秒後に再度お試しください。'
        );

        return true;
    }

    /*
     * ログアウト
     */
    public function logout(): void
    {
        AuditLog::record('logout');
        Auth::logout();
        unset($_SESSION['access_guard_pending_login'], $_SESSION['access_guard_mfa_verified'], $_SESSION['access_guard_enrollment']);

        Csrf::regenerate();

        redirect_to(
            ltrim(
                self::path(),
                '/'
            )
        );
    }

    /*
     * 元のログインURLを非表示
     */
    public function notFound(): void
    {
        http_response_code(404);

        header(
            'Cache-Control: no-store, no-cache, must-revalidate'
        );

        echo '404 Not Found';
    }

    /*
     * ログイン画面を表示
     */
    private function renderLogin(
        ?string $error = null,
        string $username = ''
    ): void {
        $title = 'ログイン';

        $action = url(
            ltrim(
                self::path(),
                '/'
            )
        );

        $csrfToken = Csrf::token();

        ob_start();
        ?>

        <div class="login-page">
            <div class="login-card">
                <h1>管理画面ログイン</h1>

                <?php if ($error !== null): ?>
                    <p class="error-message">
                        <?= e($error) ?>
                    </p>
                <?php endif; ?>

                <form
                    action="<?= e($action) ?>"
                    method="post"
                >
                    <input
                        type="hidden"
                        name="_csrf_token"
                        value="<?= e($csrfToken) ?>"
                    >

                    <div class="form-group">
                        <label for="username">
                            ユーザー名
                        </label>

                        <input
                            type="text"
                            id="username"
                            name="username"
                            value="<?= e($username) ?>"
                            autocomplete="username"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label for="password">
                            パスワード
                        </label>

                        <input
                            type="password"
                            id="password"
                            name="password"
                            autocomplete="current-password"
                            required
                        >
                    </div>

                    <button
                        type="submit"
                        class="button full"
                    >
                        ログイン
                    </button>
                </form>

                <p class="login-back">
                    <a href="<?= url('') ?>">
                        サイトへ戻る
                    </a>
                </p>
            </div>
        </div>

        <?php
        $content = ob_get_clean();

        require BASE_PATH
            . '/app/Views/admin/login-layout.php';
    }
}
