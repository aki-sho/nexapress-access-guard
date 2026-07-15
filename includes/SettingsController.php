<?php

namespace NexaPressAccessGuard;

use app\Core\Auth;
use app\Core\Csrf;
use Throwable;

/*
 * 各設定を個別に保存するコントローラー
 */
class SettingsController
{
    /*
     * ログインページアクセス制限
     */
    public function saveLoginAccess(): void
    {
        $this->authorize();

        $enabled = $this->isEnabled();

        if (
            $enabled &&
            !$this->currentIpIsAllowed()
        ) {
            $this->error(
                '現在のIPを許可IPへ追加してから有効にしてください。'
            );
        }

        $this->store(
            'login_page_access',
            ['enabled' => $enabled],
            'ログインページアクセス制限を保存しました。'
        );
    }

    /*
     * 管理ページアクセス制限
     */
    public function saveAdminAccess(): void
    {
        $this->authorize();

        $enabled = $this->isEnabled();

        if (
            $enabled &&
            !$this->currentIpIsAllowed()
        ) {
            $this->error(
                '現在のIPを許可IPへ追加してから有効にしてください。'
            );
        }

        $this->store(
            'admin_page_access',
            ['enabled' => $enabled],
            '管理ページアクセス制限を保存しました。'
        );
    }

    /*
     * ログインページURL変更
     */
    public function saveLoginUrl(): void
    {
        $this->authorize();

        $enabled = $this->isEnabled();
        $slug = strtolower(
            trim(
                (string)($_POST['slug'] ?? ''),
                " \t\n\r\0\x0B/"
            )
        );

        if ($slug === '') {
            $current = Settings::get('login_url', []);
            $slug = $current['slug'] ?? 'secure-login';
        }

        if (
            !preg_match(
                '/^[a-z0-9][a-z0-9_-]{2,63}$/',
                $slug
            )
        ) {
            $this->error(
                'ログインURLは3～64文字の半角英数字、ハイフン、アンダーバーで入力してください。'
            );
        }

        if (
            in_array(
                $slug,
                ['admin', 'login', 'install', 'public'],
                true
            )
        ) {
            $this->error(
                'このログインURLは使用できません。'
            );
        }

        $this->store(
            'login_url',
            [
                'enabled' => $enabled,
                'slug' => $slug,
            ],
            'ログインページ変更設定を保存しました。'
        );
    }

    /*
     * ログインロック
     */
    public function saveLoginLock(): void
    {
        $this->authorize();

        $attempts = $this->selectedNumber(
            'attempts',
            [3, 5, 10]
        );

        $duration = $this->selectedNumber(
            'duration',
            [5, 15, 30, 60, 360, 1440]
        );

        if ($attempts === null || $duration === null) {
            $this->error(
                'ログインロックの設定値が正しくありません。'
            );
        }

        $this->store(
            'login_lock',
            [
                'enabled' => $this->isEnabled(),
                'attempts' => $attempts,
                'duration' => $duration,
            ],
            'ログインロック設定を保存しました。'
        );
    }

    /*
     * フェールワンス
     */
    public function saveFailOnce(): void
    {
        $this->authorize();

        $count = $this->selectedNumber(
            'count',
            [1, 2, 3]
        );

        if ($count === null) {
            $this->error(
                'フェールワンスの回数が正しくありません。'
            );
        }

        $this->store(
            'fail_once',
            [
                'enabled' => $this->isEnabled(),
                'count' => $count,
            ],
            'フェールワンス設定を保存しました。'
        );
    }

    /*
     * 許可IPを追加
     */
    public function addAllowedIp(): void
    {
        $this->authorize();

        $ip = $this->postedIp();

        if ($ip === null) {
            $this->error(
                '正しいIPアドレスを入力してください。'
            );
        }

        try {
            Settings::addIp('allowed_ips', $ip);
            Settings::removeIp('denied_ips', $ip);

            Settings::setNotice(
                '許可IPを追加しました。'
            );
        } catch (Throwable $exception) {
            Settings::setNotice(
                $exception->getMessage(),
                'error'
            );
        }

        $this->redirectBack();
    }

    /*
     * 許可IPを削除
     */
    public function removeAllowedIp(): void
    {
        $this->authorize();

        $ip = $this->postedIp();

        if ($ip === null) {
            $this->error(
                '削除するIPアドレスが正しくありません。'
            );
        }

        $loginAccess = Settings::get(
            'login_page_access',
            []
        );

        $adminAccess = Settings::get(
            'admin_page_access',
            []
        );

        if (
            $ip === $this->currentIp() &&
            (
                !empty($loginAccess['enabled']) ||
                !empty($adminAccess['enabled'])
            )
        ) {
            $this->error(
                'アクセス制限中は現在のIPを許可IPから削除できません。'
            );
        }

        try {
            Settings::removeIp('allowed_ips', $ip);

            Settings::setNotice(
                '許可IPを削除しました。'
            );
        } catch (Throwable $exception) {
            Settings::setNotice(
                $exception->getMessage(),
                'error'
            );
        }

        $this->redirectBack();
    }

    /*
     * 拒否IPを追加
     */
    public function addDeniedIp(): void
    {
        $this->authorize();

        $ip = $this->postedIp();

        if ($ip === null) {
            $this->error(
                '正しいIPアドレスを入力してください。'
            );
        }

        if ($ip === $this->currentIp()) {
            $this->error(
                '現在接続しているIPは拒否できません。'
            );
        }

        try {
            Settings::addIp('denied_ips', $ip);
            Settings::removeIp('allowed_ips', $ip);

            Settings::setNotice(
                '拒否IPを追加しました。'
            );
        } catch (Throwable $exception) {
            Settings::setNotice(
                $exception->getMessage(),
                'error'
            );
        }

        $this->redirectBack();
    }

    /*
     * 拒否IPを削除
     */
    public function removeDeniedIp(): void
    {
        $this->authorize();

        $ip = $this->postedIp();

        if ($ip === null) {
            $this->error(
                '削除するIPアドレスが正しくありません。'
            );
        }

        try {
            Settings::removeIp('denied_ips', $ip);

            Settings::setNotice(
                '拒否IPを削除しました。'
            );
        } catch (Throwable $exception) {
            Settings::setNotice(
                $exception->getMessage(),
                'error'
            );
        }

        $this->redirectBack();
    }

    /*
     * ログイン状態とCSRFトークンを確認
     */
    private function authorize(): void
    {
        Auth::requireLogin();

        Csrf::requireValid(
            $_POST['_csrf_token'] ?? null
        );
    }

    /*
     * 有効・無効を取得
     */
    private function isEnabled(): bool
    {
        return isset($_POST['enabled']);
    }

    /*
     * 選択された数値を確認
     */
    private function selectedNumber(
        string $name,
        array $allowedValues
    ): ?int {
        $value = filter_var(
            $_POST[$name] ?? null,
            FILTER_VALIDATE_INT
        );

        if (
            $value === false ||
            !in_array($value, $allowedValues, true)
        ) {
            return null;
        }

        return $value;
    }

    /*
     * 送信されたIPを確認
     */
    private function postedIp(): ?string
    {
        $ip = trim(
            (string)($_POST['ip'] ?? '')
        );

        if (
            filter_var(
                $ip,
                FILTER_VALIDATE_IP
            ) === false
        ) {
            return null;
        }

        return $ip;
    }

    /*
     * 現在のIPが許可されているか確認
     */
    private function currentIpIsAllowed(): bool
    {
        $allowedIps = Settings::get(
            'allowed_ips',
            []
        );

        return is_array($allowedIps) &&
            in_array(
                $this->currentIp(),
                $allowedIps,
                true
            );
    }

    /*
     * 現在接続しているIPを取得
     */
    private function currentIp(): string
    {
        return (string)(
            $_SERVER['REMOTE_ADDR'] ?? ''
        );
    }

    /*
     * 設定を保存
     */
    private function store(
        string $section,
        mixed $value,
        string $message
    ): void {
        try {
            Settings::saveSection(
                $section,
                $value
            );

            Settings::setNotice($message);
        } catch (Throwable $exception) {
            Settings::setNotice(
                $exception->getMessage(),
                'error'
            );
        }

        $this->redirectBack();
    }

    /*
     * エラーを表示して設定画面へ戻す
     */
    private function error(string $message): void
    {
        Settings::setNotice(
            $message,
            'error'
        );

        $this->redirectBack();
    }

    /*
     * 設定画面へ戻る
     */
    private function redirectBack(): void
    {
        redirect_to(
            'admin/extensions/access-guard/dashboard'
        );
    }
}