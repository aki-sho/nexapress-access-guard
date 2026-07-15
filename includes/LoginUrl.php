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

        $this->renderLogin();
    }

    /*
     * ログイン処理
     */
    public function authenticate(): void
    {
        Csrf::requireValid(
            $_POST['_csrf_token'] ?? null
        );

        $ip = IpRules::currentIp();

        /*
         * ロック中は認証処理を行わない
         */
        if (LoginLock::isLocked($ip)) {
            $minutes =
                LoginLock::remainingMinutes($ip);

            $this->renderLogin(
                'ログインが一時的にロックされています。'
                . '約'
                . $minutes
                . '分後に再度お試しください。'
            );

            return;
        }

        $email = trim(
            (string)($_POST['email'] ?? '')
        );

        $password =
            (string)($_POST['password'] ?? '');

        if ($email === '' || $password === '') {
            $this->renderLogin(
                'メールアドレスとパスワードを入力してください。',
                $email
            );

            return;
        }

        $user = User::findByEmail($email);

        if (
            !$user ||
            !password_verify(
                $password,
                $user['password_hash']
            )
        ) {
            $locked =
                LoginLock::recordFailure($ip);

            $message = $locked
                ? 'ログイン失敗回数が上限に達したため、'
                    . '一時的にロックしました。'
                : 'ログイン情報が正しくありません。';

            $this->renderLogin(
                $message,
                $email
            );

            return;
        }

        /*
         * 正しい認証情報でも指定回数だけ失敗させる
         */
        if (
            FailOnce::shouldReject(
                $ip,
                $email
            )
        ) {
            $this->renderLogin(
                'ログイン情報が正しくありません。',
                $email
            );

            return;
        }

        /*
         * ログイン成功
         */
        LoginLock::clear($ip);

        FailOnce::clear(
            $ip,
            $email
        );

        session_regenerate_id(true);

        Auth::login($user);

        Csrf::regenerate();

        redirect_to('admin');
    }

    /*
     * ログアウト
     */
    public function logout(): void
    {
        Auth::logout();

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
        string $email = ''
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
                        <label for="email">
                            メールアドレス
                        </label>

                        <input
                            type="email"
                            id="email"
                            name="email"
                            value="<?= e($email) ?>"
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