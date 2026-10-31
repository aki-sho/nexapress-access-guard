<?php

namespace NexaPressAccessGuard;

use RuntimeException;

class StorageException extends RuntimeException
{
}

/*
 * 別ファイルのロックと原子的な置換でJSONを保存する。
 * 既存データの異常は初期値へ戻さず、呼び出し元へ通知する。
 */
class JsonStorage
{
    public static function read(
        string $path,
        array $initial,
        callable $validate
    ): array {
        return self::withLock($path, LOCK_SH, static function () use (
            $path, $initial, $validate
        ): array {
            return self::readUnlocked($path, $initial, $validate);
        });
    }

    public static function update(
        string $path,
        array $initial,
        callable $validate,
        callable $callback,
        bool $backup = false
    ): mixed {
        return self::withLock($path, LOCK_EX, static function () use (
            $path, $initial, $validate, $callback, $backup
        ): mixed {
            $data = self::readUnlocked($path, $initial, $validate);
            $result = $callback($data);
            $data = $validate($data);
            $json = json_encode(
                $data,
                JSON_UNESCAPED_UNICODE |
                JSON_UNESCAPED_SLASHES |
                JSON_PRETTY_PRINT
            );

            if ($json === false) {
                throw new StorageException('保護データを作成できません。');
            }

            if ($backup) {
                self::replace($path . '.bak', $json);
            }

            self::replace($path, $json);

            return $result;
        });
    }

    public static function unavailable(): void
    {
        http_response_code(503);
        header('Cache-Control: no-store');
        header('Retry-After: 60');
        exit('保護データを読み書きできないため、処理を停止しました。管理者へお問い合わせください。');
    }

    /* CLIからのみ呼ぶ復旧操作。破損した元ファイルを読み込まず置き換える。 */
    public static function restore(string $path, callable $validate): void
    {
        self::withLock($path, LOCK_EX, static function () use ($path, $validate): void {
            if (!is_file($path . '.bak')) {
                throw new StorageException('復旧に使用できるバックアップがありません。');
            }

            $data = self::readUnlocked($path . '.bak', [], $validate);
            $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

            if ($json === false) {
                throw new StorageException('バックアップを復旧できません。');
            }

            self::replace($path, $json);
        });
    }

    private static function withLock(
        string $path,
        int $mode,
        callable $callback
    ): mixed {
        $directory = dirname($path);

        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new StorageException('保護データの保存フォルダを作成できません。');
        }

        $handle = @fopen($path . '.lock', 'c');

        if ($handle === false) {
            throw new StorageException('保護データのロックを開けません。');
        }

        try {
            if (!flock($handle, $mode)) {
                throw new StorageException('保護データをロックできません。');
            }

            return $callback();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private static function readUnlocked(
        string $path,
        array $initial,
        callable $validate
    ): array {
        clearstatcache(true, $path);

        if (!file_exists($path)) {
            if (file_exists($path . '.bak')) {
                throw new StorageException('保護データが見つかりません。バックアップから復旧してください。');
            }

            return $validate($initial);
        }

        $json = @file_get_contents($path);

        if ($json === false) {
            throw new StorageException('保護データを読み込めません。');
        }

        $data = json_decode($json, true);

        if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
            throw new StorageException('保護データが破損しています。バックアップから復旧してください。');
        }

        return $validate($data);
    }

    private static function replace(string $path, string $json): void
    {
        $temporary = @tempnam(dirname($path), '.access-guard-');

        if ($temporary === false) {
            throw new StorageException('保護データの一時ファイルを作成できません。');
        }

        $handle = null;

        try {
            @chmod($temporary, 0600);
            $handle = @fopen($temporary, 'wb');

            if ($handle === false) {
                throw new StorageException('保護データの一時ファイルを開けません。');
            }

            $length = strlen($json);
            $offset = 0;

            while ($offset < $length) {
                $written = fwrite($handle, substr($json, $offset));

                if ($written === false || $written === 0) {
                    throw new StorageException('保護データを保存できません。');
                }

                $offset += $written;
            }

            if (!fflush($handle) || (function_exists('fsync') && !fsync($handle))) {
                throw new StorageException('保護データを確定できません。');
            }

            fclose($handle);
            $handle = null;

            if (!@rename($temporary, $path)) {
                throw new StorageException('保護データを置き換えられません。');
            }
        } finally {
            if (is_resource($handle)) {
                fclose($handle);
            }

            if (is_file($temporary)) {
                unlink($temporary);
            }
        }
    }
}
