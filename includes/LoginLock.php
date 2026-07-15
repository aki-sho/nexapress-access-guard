<?php

namespace NexaPressAccessGuard;

use RuntimeException;

/*
 * ログイン失敗回数と一時ロックを管理
 */
class LoginLock
{
    /*
     * 現在ロック中か確認
     */
    public static function isLocked(
        string $ip
    ): bool {
        if (!self::isEnabled()) {
            return false;
        }

        return self::withData(
            static function (
                array &$data
            ) use ($ip): bool {
                if (!isset($data[$ip])) {
                    return false;
                }

                $lockedUntil = (int)(
                    $data[$ip]['locked_until'] ?? 0
                );

                if ($lockedUntil <= time()) {
                    if ($lockedUntil > 0) {
                        unset($data[$ip]);
                    }

                    return false;
                }

                return true;
            }
        );
    }

    /*
     * ログイン失敗を記録
     *
     * 戻り値：
     * true  ロックされた
     * false まだロックされていない
     */
    public static function recordFailure(
        string $ip
    ): bool {
        if (!self::isEnabled()) {
            return false;
        }

        $setting = Settings::get(
            'login_lock',
            []
        );

        $attempts = max(
            1,
            (int)($setting['attempts'] ?? 5)
        );

        $duration = max(
            1,
            (int)($setting['duration'] ?? 30)
        );

        return self::withData(
            static function (
                array &$data
            ) use (
                $ip,
                $attempts,
                $duration
            ): bool {
                $entry = $data[$ip] ?? [
                    'count' => 0,
                    'locked_until' => 0,
                    'updated_at' => 0,
                ];

                /*
                 * すでにロック中
                 */
                if (
                    (int)$entry['locked_until'] >
                    time()
                ) {
                    return true;
                }

                $entry['count'] =
                    (int)$entry['count'] + 1;

                $entry['updated_at'] = time();

                /*
                 * 上限に到達
                 */
                if (
                    $entry['count'] >=
                    $attempts
                ) {
                    $entry['count'] = 0;

                    $entry['locked_until'] =
                        time() +
                        ($duration * 60);

                    $data[$ip] = $entry;

                    return true;
                }

                $entry['locked_until'] = 0;

                $data[$ip] = $entry;

                return false;
            }
        );
    }

    /*
     * 残りロック時間を分で取得
     */
    public static function remainingMinutes(
        string $ip
    ): int {
        if (!self::isEnabled()) {
            return 0;
        }

        return self::withData(
            static function (
                array &$data
            ) use ($ip): int {
                $lockedUntil = (int)(
                    $data[$ip]['locked_until'] ?? 0
                );

                if ($lockedUntil <= time()) {
                    unset($data[$ip]);

                    return 0;
                }

                return max(
                    1,
                    (int)ceil(
                        ($lockedUntil - time()) /
                        60
                    )
                );
            }
        );
    }

    /*
     * ログイン失敗情報を削除
     */
    public static function clear(
        string $ip
    ): void {
        self::withData(
            static function (
                array &$data
            ) use ($ip): null {
                unset($data[$ip]);

                return null;
            }
        );
    }

    /*
     * ログインロックが有効か確認
     */
    private static function isEnabled(): bool
    {
        $setting = Settings::get(
            'login_lock',
            []
        );

        return !empty($setting['enabled']);
    }

    /*
     * ロックファイルを安全に読み書き
     */
    private static function withData(
        callable $callback
    ): mixed {
        $path = self::storagePath();
        $directory = dirname($path);

        if (
            !is_dir($directory) &&
            !mkdir($directory, 0755, true)
        ) {
            throw new RuntimeException(
                'ログインロック保存フォルダを作成できません。'
            );
        }

        $handle = fopen($path, 'c+');

        if ($handle === false) {
            throw new RuntimeException(
                'ログインロック情報を開けません。'
            );
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException(
                    'ログインロック情報を固定できません。'
                );
            }

            rewind($handle);

            $json = stream_get_contents($handle);

            $data = json_decode(
                (string)$json,
                true
            );

            if (!is_array($data)) {
                $data = [];
            }

            $result = $callback($data);

            $encoded = json_encode(
                $data,
                JSON_UNESCAPED_UNICODE |
                JSON_UNESCAPED_SLASHES |
                JSON_PRETTY_PRINT
            );

            if ($encoded === false) {
                throw new RuntimeException(
                    'ログインロック情報を作成できません。'
                );
            }

            rewind($handle);
            ftruncate($handle, 0);

            if (fwrite($handle, $encoded) === false) {
                throw new RuntimeException(
                    'ログインロック情報を保存できません。'
                );
            }

            fflush($handle);

            return $result;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /*
     * 保存場所
     */
    private static function storagePath(): string
    {
        return BASE_PATH
            . '/storage/extensions/access-guard/login-locks.json';
    }
}