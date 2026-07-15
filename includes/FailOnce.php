<?php

namespace NexaPressAccessGuard;

use RuntimeException;

/*
 * 正しいログインでも指定回数だけ失敗させる
 */
class FailOnce
{
    /*
     * ログインを意図的に失敗させるか確認
     */
    public static function shouldReject(
        string $ip,
        string $email
    ): bool {
        $setting = Settings::get(
            'fail_once',
            []
        );

        if (empty($setting['enabled'])) {
            return false;
        }

        /*
         * 許可IPはフェールワンス対象外
         */
        if (IpRules::isAllowed($ip)) {
            return false;
        }

        $requiredCount = max(
            1,
            min(
                3,
                (int)($setting['count'] ?? 1)
            )
        );

        $key = self::key(
            $ip,
            $email
        );

        return self::withData(
            static function (
                array &$data
            ) use (
                $key,
                $requiredCount
            ): bool {
                self::removeExpired($data);

                $entry = $data[$key] ?? [
                    'count' => 0,
                    'updated_at' => 0,
                ];

                /*
                 * 10分以上経過した場合は回数をリセット
                 */
                if (
                    (int)$entry['updated_at'] <
                    time() - 600
                ) {
                    $entry = [
                        'count' => 0,
                        'updated_at' => 0,
                    ];
                }

                /*
                 * 指定回数の失敗が完了済み
                 */
                if (
                    (int)$entry['count'] >=
                    $requiredCount
                ) {
                    return false;
                }

                $entry['count'] =
                    (int)$entry['count'] + 1;

                $entry['updated_at'] = time();

                $data[$key] = $entry;

                return true;
            }
        );
    }

    /*
     * ログイン成功後に記録を削除
     */
    public static function clear(
        string $ip,
        string $email
    ): void {
        $key = self::key(
            $ip,
            $email
        );

        self::withData(
            static function (
                array &$data
            ) use ($key): null {
                unset($data[$key]);

                return null;
            }
        );
    }

    /*
     * IPとメールアドレスから保存キーを作成
     */
    private static function key(
        string $ip,
        string $email
    ): string {
        return hash(
            'sha256',
            $ip
            . '|'
            . strtolower(trim($email))
        );
    }

    /*
     * 古い記録を削除
     */
    private static function removeExpired(
        array &$data
    ): void {
        $expiredTime =
            time() - 86400;

        foreach ($data as $key => $entry) {
            $updatedAt = (int)(
                $entry['updated_at'] ?? 0
            );

            if ($updatedAt < $expiredTime) {
                unset($data[$key]);
            }
        }
    }

    /*
     * フェールワンス情報を安全に読み書き
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
                'フェールワンス保存フォルダを作成できません。'
            );
        }

        $handle = fopen($path, 'c+');

        if ($handle === false) {
            throw new RuntimeException(
                'フェールワンス情報を開けません。'
            );
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException(
                    'フェールワンス情報を固定できません。'
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
                    'フェールワンス情報を作成できません。'
                );
            }

            rewind($handle);
            ftruncate($handle, 0);

            if (fwrite($handle, $encoded) === false) {
                throw new RuntimeException(
                    'フェールワンス情報を保存できません。'
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
            . '/storage/extensions/access-guard/fail-once.json';
    }
}