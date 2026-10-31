<?php

namespace NexaPressAccessGuard;

use RuntimeException;

class TwoFactor
{
    public static function path(): string
    {
        return BASE_PATH . '/storage/extensions/access-guard/two-factor.json';
    }

    public static function all(): array
    {
        return JsonStorage::read(self::path(), [], [self::class, 'validate']);
    }

    public static function enabled(int $id): bool
    {
        return isset(self::all()[(string)$id]);
    }

    public static function version(int $id): ?string
    {
        return self::all()[$id]['version'] ?? null;
    }

    public static function enroll(int $id, string $secret, string $code): array
    {
        $counter = Totp::counter($secret, $code, time());

        if ($counter === null) {
            throw new RuntimeException('確認コードが正しくありません。');
        }

        $codes = self::recoveryCodes();
        $encrypted = SecretCipher::encrypt($secret, $id);

        JsonStorage::update(self::path(), [], [self::class, 'validate'],
            static function (array &$data) use ($id, $encrypted, $counter, $codes): void {
                if ($id < 1 || isset($data[$id])) {
                    throw new RuntimeException('このアカウントはすでに二要素認証が有効です。');
                }

                $data[$id] = [
                    'secret' => $encrypted,
                    'version' => bin2hex(random_bytes(16)),
                    'last_counter' => $counter,
                    'recovery' => array_map([self::class, 'hashRecovery'], $codes),
                    'failures' => 0,
                    'locked_until' => 0,
                ];
            }, true);

        return $codes;
    }

    /* 確認と消費を同じロック内で処理し、OTP・復旧コードの再利用を防ぐ。 */
    public static function verify(int $id, string $code, string $action = 'login'): array
    {
        if (!in_array($action, ['login', 'disable', 'regenerate'], true)) {
            throw new RuntimeException('不正な二要素認証操作です。');
        }

        return JsonStorage::update(self::path(), [], [self::class, 'validate'],
            static function (array &$data) use ($id, $code, $action): array {
                if (!isset($data[$id])) {
                    return ['valid' => false];
                }

                $entry = &$data[$id];

                if ($entry['locked_until'] > time()) {
                    return ['valid' => false];
                }

                if ($entry['locked_until'] > 0) {
                    $entry['failures'] = 0;
                    $entry['locked_until'] = 0;
                }

                $counter = Totp::counter(SecretCipher::decrypt($entry['secret'], $id), trim($code), time(), $entry['last_counter']);
                $hash = self::hashRecovery($code);
                $recoveryIndex = null;

                foreach ($entry['recovery'] as $index => $savedHash) {
                    if (hash_equals($savedHash, $hash)) {
                        $recoveryIndex = $index;
                    }
                }

                if ($counter === null && $recoveryIndex === null) {
                    $entry['failures']++;

                    if ($entry['failures'] >= 5) {
                        $entry['locked_until'] = time() + 300;
                    }

                    return ['valid' => false];
                }

                $entry['failures'] = 0;
                $entry['locked_until'] = 0;

                if ($counter !== null) {
                    $entry['last_counter'] = $counter;
                } else {
                    unset($entry['recovery'][$recoveryIndex]);
                    $entry['recovery'] = array_values($entry['recovery']);
                }

                $result = ['valid' => true, 'recovery' => $counter === null];

                if ($action === 'disable') {
                    unset($data[$id]);
                } elseif ($action === 'regenerate') {
                    $result['codes'] = self::recoveryCodes();
                    $entry['recovery'] = array_map([self::class, 'hashRecovery'], $result['codes']);
                    $entry['version'] = bin2hex(random_bytes(16));
                }

                $result['version'] = $action === 'disable' ? null : $entry['version'];

                return $result;
            }, true);
    }

    public static function reset(int $id): void
    {
        JsonStorage::update(self::path(), [], [self::class, 'validate'],
            static function (array &$data) use ($id): void { unset($data[$id]); }, true);
    }

    private static function recoveryCodes(): array
    {
        return array_map(static fn() => implode('-', str_split(bin2hex(random_bytes(10)), 5)), range(1, 10));
    }

    public static function hashRecovery(string $code): string
    {
        return hash('sha256', strtolower(str_replace(['-', ' '], '', trim($code))));
    }

    public static function validate(array $data): array
    {
        foreach ($data as $id => $entry) {
            if (!ctype_digit((string)$id) || (int)$id < 1 || !is_array($entry) ||
                !isset($entry['secret'], $entry['recovery'], $entry['version']) || !is_string($entry['secret']) ||
                !is_string($entry['version']) || !preg_match('/^[a-f0-9]{32}$/D', $entry['version']) || !is_array($entry['recovery'])) {
                throw new StorageException('二要素認証の保存データが正しくありません。');
            }

            foreach (['last_counter', 'failures', 'locked_until'] as $field) {
                if (!isset($entry[$field]) || !is_int($entry[$field]) || $entry[$field] < 0) {
                    throw new StorageException('二要素認証の保存データが正しくありません。');
                }
            }

            foreach ($entry['recovery'] as $hash) {
                if (!is_string($hash) || !preg_match('/^[a-f0-9]{64}$/D', $hash)) {
                    throw new StorageException('復旧コードの保存データが正しくありません。');
                }
            }
        }

        return $data;
    }
}
