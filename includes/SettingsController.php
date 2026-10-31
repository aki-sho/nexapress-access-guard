<?php

namespace NexaPressAccessGuard;

use app\Core\Csrf;
use app\Core\Permission;
use Throwable;

/*
 * 各設定を個別に保存するコントローラー
 */
class SettingsController
{
    public function saveTrustedProxy(): void
    {
        $this->authorize();
        $networks = preg_split('/[\s,]+/', trim((string)($_POST['proxies'] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
        $setting = [
            'enabled' => $this->isEnabled(),
            'proxies' => $networks,
            'header' => (string)($_POST['header'] ?? 'x-forwarded-for'),
        ];

        try {
            $settings = Settings::all();
            $settings['trusted_proxy'] = $setting;
            $settings = Settings::validate($settings);
            $newIp = IpRules::resolve($_SERVER, $settings['trusted_proxy']);

            if ($newIp === '' || IpRules::isDenied($newIp) ||
                (($settings['login_page_access']['enabled'] || $settings['admin_page_access']['enabled']) && !IpRules::isAllowed($newIp))) {
                $this->error('変更後の接続元IPが許可されないため保存できません。先に利用者IPを許可IPへ登録してください。');
                return;
            }

            $this->store('trusted_proxy', $settings['trusted_proxy'], '信頼済みプロキシ設定を保存しました。');
        } catch (Throwable $exception) {
            $this->error($exception->getMessage());
        }
    }

    public function saveMonitoring(): void
    {
        $this->authorize();
        $retention = $this->selectedNumber('retention_days', [7, 30, 90]);
        $threshold = $this->selectedNumber('failure_threshold', [5, 10, 20, 50]);

        if ($retention === null || $threshold === null) {
            $this->error('監視設定の値が正しくありません。');
            return;
        }

        try {
            // 片方の検証に失敗した場合も両方の設定を変更しない。
            $settings = Settings::all();
            $notification = [
                'enabled' => $this->isEnabled(),
                'email' => trim((string)($_POST['email'] ?? '')),
                'failure_threshold' => $threshold,
            ];
            $settings['notifications'] = $notification;
            Settings::validate($settings);
            Settings::saveSections([
                'notifications' => $notification,
                'audit' => ['retention_days' => $retention],
            ]);
            Settings::setNotice('監査ログ・異常通知の設定を保存しました。');
        } catch (Throwable $exception) {
            Settings::setNotice($exception->getMessage(), 'error');
        }

        $this->redirectBack();
    }

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
     * 拡張機能の管理権限とCSRFトークンを確認
     */
    private function authorize(): void
    {
        Permission::require('extensions.manage');

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
        return IpRules::normalize(
            (string)($_POST['ip'] ?? '')
        );
    }

    /*
     * 現在のIPが許可されているか確認
     */
    private function currentIpIsAllowed(): bool
    {
        return IpRules::isAllowed($this->currentIp());
    }

    /*
     * 現在接続しているIPを取得
     */
    private function currentIp(): string
    {
        return IpRules::currentIp();
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
