<?php

namespace NexaPressAccessGuard;

use app\Core\Auth;
use app\Core\Csrf;
use app\Models\User;
use RuntimeException;

class TwoFactorController
{
    private const MAX_ENROLLMENT_ATTEMPTS = 5;

    public function show(): void
    {
        try {
            $this->render();
        } catch (StorageException $exception) {
            JsonStorage::unavailable();
        }
    }

    public function save(): void
    {
        Auth::requireLogin();
        Csrf::requireValid($_POST['_csrf_token'] ?? null);

        try {
            $user = $this->user();
            $id = (int)$user['id'];
            $action = $_POST['_action'] ?? null;
            $password = $_POST['password'] ?? '';
            $code = $_POST['code'] ?? '';

            if (!is_string($code) || !is_string($password)) {
                throw new RuntimeException('入力内容が正しくありません。');
            }

            if ($action === 'enable') {
                $pending = $this->pendingEnrollment($user);
                if ($pending === null) {
                    throw new RuntimeException('登録を開始してから確認コードを入力してください。');
                }
                try {
                    $codes = TwoFactor::enroll($id, $pending['secret'], $code);
                } catch (InvalidEnrollmentCode $exception) {
                    $attempts = ($pending['attempts'] ?? 0) + 1;
                    if ($attempts >= self::MAX_ENROLLMENT_ATTEMPTS) {
                        unset($_SESSION['access_guard_enrollment']);
                    } else {
                        $_SESSION['access_guard_enrollment']['attempts'] = $attempts;
                    }
                    AuditLog::record('mfa_management_failure', $user['username']);
                    throw new RuntimeException($attempts >= self::MAX_ENROLLMENT_ATTEMPTS
                        ? '確認コードの試行回数に達しました。登録をやり直してください。'
                        : $exception->getMessage());
                }

                unset($_SESSION['access_guard_enrollment']);
                $_SESSION['access_guard_mfa_verified'] = TwoFactor::version($id);
                AuditLog::record('mfa_enabled', $user['username']);
                $this->render(null, $codes);
                return;
            }

            if (!password_verify($password, $user['password_hash'])) {
                AuditLog::record('mfa_management_failure', $user['username']);
                throw new RuntimeException('現在のパスワードが正しくありません。');
            }

            if ($action === 'begin') {
                if (!function_exists('openssl_encrypt')) {
                    throw new RuntimeException('二要素認証を利用するには、サーバーのPHP OpenSSL拡張を有効にしてください。');
                }

                if (TwoFactor::enabled($id)) {
                    throw new RuntimeException('二要素認証はすでに有効です。');
                }

                $_SESSION['access_guard_enrollment'] = [
                    'id' => $id,
                    'secret' => Totp::secret(),
                    'expires' => time() + 300,
                    'password' => hash('sha256', $user['password_hash']),
                ];
                $this->render();
                return;
            }

            if (!in_array($action, ['disable', 'regenerate'], true)) {
                throw new RuntimeException('操作が正しくありません。');
            }

            $result = TwoFactor::verify($id, $code, $action);

            if (!$result['valid']) {
                AuditLog::record('mfa_failure', $user['username']);
                throw new RuntimeException('確認コードが正しくないか、一時的に制限されています。');
            }

            $_SESSION['access_guard_mfa_verified'] = $result['version'];
            AuditLog::record($action === 'disable' ? 'mfa_disabled' : 'recovery_regenerated', $user['username']);
            $this->render(null, $result['codes'] ?? []);
        } catch (StorageException $exception) {
            JsonStorage::unavailable();
        } catch (RuntimeException $exception) {
            $this->render($exception->getMessage());
        }
    }

    private function user(): array
    {
        Auth::requireLogin();
        $sessionUser = Auth::user();
        $user = User::findByUsername((string)($sessionUser['username'] ?? ''));

        if (!$user || (int)$user['id'] !== (int)($sessionUser['id'] ?? 0)) {
            Auth::logout();
            redirect_to(ltrim(LoginUrl::path(), '/'));
        }

        return $user;
    }

    private function pendingEnrollment(array $user): ?array
    {
        $pending = $_SESSION['access_guard_enrollment'] ?? null;
        if (!is_array($pending) || ($pending['id'] ?? null) !== (int)$user['id'] ||
            ($pending['expires'] ?? 0) <= time() ||
            !hash_equals($pending['password'] ?? '', hash('sha256', $user['password_hash'])) ||
            ($pending['attempts'] ?? 0) >= self::MAX_ENROLLMENT_ATTEMPTS) {
            unset($_SESSION['access_guard_enrollment']);
            return null;
        }

        return $pending;
    }

    private function render(?string $error = null, array $codes = []): void
    {
        $user = $this->user();
        $active = TwoFactor::enabled((int)$user['id']);
        $pending = $this->pendingEnrollment($user);
        $uri = null;
        $qr = null;
        if (!$active && $pending !== null) {
            $uri = 'otpauth://totp/NexaPress:' . rawurlencode($user['username'])
                . '?secret=' . rawurlencode($pending['secret'])
                . '&issuer=NexaPress&algorithm=SHA1&digits=6&period=30';
            $qr = EnrollmentQr::render($uri);
        }

        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        header('X-Frame-Options: DENY');
        header("Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        $title = '二要素認証';
        $csrfToken = Csrf::token();
        $action = url('admin/access-guard/two-factor');
        ob_start();
        require dirname(__DIR__) . '/admin/two-factor.php';
        $content = ob_get_clean();
        require BASE_PATH . '/app/Views/admin/login-layout.php';
    }
}
