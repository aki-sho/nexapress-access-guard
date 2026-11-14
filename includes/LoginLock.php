<?php

namespace NexaPressAccessGuard;

/* IPとアカウントの両方でログイン失敗・待機時間を管理する。 */
class LoginLock
{
    private const OBSERVATION_SECONDS = 900;
    private const ACCOUNT_WAIT_SECONDS = 30;

    public static function isLocked(string $ip, string $username = ''): bool
    {
        return self::retryAfterSeconds($ip, $username) > 0;
    }

    public static function retryAfterSeconds(string $ip, string $username = '', bool $trusted = false): int
    {
        if (!self::isEnabled()) {
            return 0;
        }

        $data = JsonStorage::read(self::storagePath(), [], [self::class, 'validate']);
        $now = time();
        $wait = 0;

        foreach (self::keys($ip, $trusted ? '' : $username) as $key) {
            $wait = max($wait, self::waitUntil($key, $data[$key] ?? []) - $now);
        }

        return $wait;
    }

    public static function recordFailure(string $ip, string $username = '', bool $trusted = false): bool
    {
        if (!self::isEnabled()) {
            return false;
        }

        $setting = Settings::get('login_lock');

        return JsonStorage::update(
            self::storagePath(),
            [],
            [self::class, 'validate'],
            static function (array &$data) use ($ip, $username, $setting, $trusted): bool {
                $now = time();
                self::removeExpired($data, $now);
                $locked = false;

                foreach (self::keys($ip, $trusted ? '' : $username) as $key) {
                    $entry = $data[$key] ?? [
                        'count' => 0,
                        'locked_until' => 0,
                        'updated_at' => $now,
                        'next_attempt_at' => 0,
                    ];

                    if ($entry['locked_until'] > $now) {
                        $locked = true;
                        continue;
                    }

                    $entry['count']++;
                    $entry['updated_at'] = $now;

                    if ($entry['count'] >= $setting['attempts']) {
                        $entry['locked_until'] = $now + (str_starts_with($key, 'account:')
                            ? self::ACCOUNT_WAIT_SECONDS
                            : $setting['duration'] * 60);
                        $entry['next_attempt_at'] = 0;
                        $locked = true;
                    } else {
                        // 2回目以降は1・2・4…秒（最大30秒）の待機。
                        $entry['next_attempt_at'] = $entry['count'] < 2
                            ? 0
                            : $now + min(30, 2 ** min(5, $entry['count'] - 2));
                    }

                    $data[$key] = $entry;
                }

                return $locked;
            },
            true
        );
    }

    public static function remainingMinutes(string $ip, string $username = ''): int
    {
        return (int)ceil(self::retryAfterSeconds($ip, $username) / 60);
    }

    /* 成功したアカウントだけをリセットし、IP全体の攻撃履歴は残す。 */
    public static function clear(string $ip, string $username = '', bool $trusted = false): bool
    {
        if (!self::isEnabled()) {
            return true;
        }

        return JsonStorage::update(
            self::storagePath(),
            [],
            [self::class, 'validate'],
            static function (array &$data) use ($ip, $username, $trusted): bool {
                $now = time();
                // ロックの最終確認とカウンタのリセットを同じ排他ロック内で行う。
                foreach (self::keys($ip, $trusted ? '' : $username) as $key) {
                    if (self::waitUntil($key, $data[$key] ?? []) > $now) {
                        return false;
                    }
                }

                $key = trim($username) === '' ? self::keys($ip, '')[0] : self::accountKey($username);
                unset($data[$key]);
                self::removeExpired($data, $now);

                return true;
            },
            true
        );
    }

    private static function keys(string $ip, string $username): array
    {
        // IPのキーは従来形式を維持し、既存のロックを引き継ぐ。
        $keys = [IpRules::normalize($ip) ?? 'unknown'];

        if (trim($username) !== '') {
            $keys[] = self::accountKey($username);
        }

        return $keys;
    }

    private static function accountKey(string $username): string
    {
        return 'account:' . hash('sha256', strtolower(trim($username)));
    }

    private static function waitUntil(string $key, array $entry): int
    {
        $until = $entry['locked_until'] ?? 0;
        if (str_starts_with($key, 'account:')) {
            $until = min($until, ($entry['updated_at'] ?? 0) + self::ACCOUNT_WAIT_SECONDS);
        }

        return max($until, $entry['next_attempt_at'] ?? 0);
    }

    public static function reset(?string $ip, string $username): void
    {
        $keys = [];

        if ($ip !== null) {
            $keys[] = IpRules::normalize($ip) ?? 'unknown';
        }

        if (trim($username) !== '') {
            $keys[] = self::accountKey($username);
        }

        JsonStorage::update(self::storagePath(), [], [self::class, 'validate'],
            static function (array &$data) use ($keys): void {
                foreach ($keys as $key) {
                    unset($data[$key]);
                }
            }, true);
    }

    public static function validate(array $data): array
    {
        $normalized = [];

        foreach ($data as $key => $entry) {
            $ip = is_string($key) ? IpRules::normalize($key) : null;

            if ($ip === null && $key !== 'unknown' &&
                (!is_string($key) || !preg_match('/^account:[a-f0-9]{64}$/', $key))) {
                throw new StorageException('ログインロックのキーが正しくありません。');
            }

            if (!is_array($entry)) {
                throw new StorageException('ログインロックの形式が正しくありません。');
            }

            // 旧版にない待機時刻は0として読み込める。
            $entry['next_attempt_at'] = $entry['next_attempt_at'] ?? 0;

            foreach (['count', 'locked_until', 'updated_at', 'next_attempt_at'] as $field) {
                if (!isset($entry[$field]) || !is_int($entry[$field]) || $entry[$field] < 0) {
                    throw new StorageException('ログインロックの値が正しくありません。');
                }
            }

            $key = $ip ?? $key;

            if (isset($normalized[$key])) {
                foreach (['count', 'locked_until', 'updated_at', 'next_attempt_at'] as $field) {
                    $entry[$field] = max($entry[$field], $normalized[$key][$field]);
                }
            }

            $normalized[$key] = $entry;
        }

        return $normalized;
    }

    private static function removeExpired(array &$data, int $now): void
    {
        foreach ($data as $key => $entry) {
            $expiredLock = $entry['locked_until'] > 0 && self::waitUntil($key, $entry) <= $now;
            $expiredFailures = $entry['locked_until'] === 0 &&
                $entry['updated_at'] + self::OBSERVATION_SECONDS <= $now;

            if ($expiredLock || $expiredFailures) {
                unset($data[$key]);
            }
        }
    }

    private static function isEnabled(): bool
    {
        return Settings::get('login_lock')['enabled'];
    }

    private static function storagePath(): string
    {
        return BASE_PATH . '/storage/extensions/access-guard/login-locks.json';
    }
}
