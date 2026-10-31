<?php

namespace NexaPressAccessGuard;

class SecretCipher
{
    private static function key(bool $create): string
    {
        if (!function_exists('openssl_encrypt')) {
            throw new StorageException('二要素認証にはPHP OpenSSL拡張が必要です。');
        }

        $path = BASE_PATH . '/storage/extensions/access-guard/two-factor.key';
        $validate = static function (array $data): array {
            if (!isset($data['key']) || !is_string($data['key']) ||
                strlen((string)base64_decode($data['key'], true)) !== 32) {
                throw new StorageException('二要素認証の暗号鍵が正しくありません。');
            }

            return $data;
        };

        if (!$create) {
            $data = JsonStorage::read($path, [], $validate);
            return base64_decode($data['key'], true);
        }

        return JsonStorage::update($path, ['key' => base64_encode(random_bytes(32))], $validate,
            static fn(array &$data): string => base64_decode($data['key'], true));
    }

    public static function encrypt(string $secret, int $userId): string
    {
        $nonce = random_bytes(12);
        $tag = '';
        $key = self::key(true);
        $encrypted = openssl_encrypt($secret, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, (string)$userId);

        if ($encrypted === false) {
            throw new StorageException('二要素認証の秘密鍵を保存できません。');
        }

        return base64_encode($nonce . $tag . $encrypted);
    }

    public static function decrypt(string $encrypted, int $userId): string
    {
        $key = self::key(false);
        $bytes = base64_decode($encrypted, true);

        if ($bytes === false || strlen($bytes) < 29) {
            throw new StorageException('二要素認証の秘密鍵が破損しています。');
        }

        $secret = openssl_decrypt(substr($bytes, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA,
            substr($bytes, 0, 12), substr($bytes, 12, 16), (string)$userId);

        if ($secret === false || !preg_match('/^[A-Z2-7]{32}$/D', $secret)) {
            throw new StorageException('二要素認証の秘密鍵を復号できません。');
        }

        return $secret;
    }
}
