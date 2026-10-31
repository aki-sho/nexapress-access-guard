<?php

namespace NexaPressAccessGuard;

use InvalidArgumentException;

/* RFC 6238 / SHA-1、30秒、通常6桁。外部サービスへ秘密鍵を送らない。 */
class Totp
{
    public static function secret(): string
    {
        return self::encode(random_bytes(20));
    }

    public static function encode(string $bytes): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $buffer = 0;
        $bits = 0;
        $result = '';

        foreach (unpack('C*', $bytes) as $byte) {
            $buffer = ($buffer << 8) | $byte;
            $bits += 8;

            while ($bits >= 5) {
                $bits -= 5;
                $result .= $alphabet[($buffer >> $bits) & 31];
            }

            $buffer &= (1 << $bits) - 1;
        }

        return $result . ($bits > 0 ? $alphabet[($buffer << (5 - $bits)) & 31] : '');
    }

    public static function code(string $secret, int $timestamp, int $digits = 6): string
    {
        if ($timestamp < 0 || !in_array($digits, [6, 8], true) || !preg_match('/^[A-Z2-7]{16,128}$/', $secret)) {
            throw new InvalidArgumentException('TOTPの入力が正しくありません。');
        }

        $key = '';
        $buffer = 0;
        $bits = 0;

        foreach (str_split($secret) as $character) {
            $buffer = ($buffer << 5) | strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $character);
            $bits += 5;

            if ($bits >= 8) {
                $bits -= 8;
                $key .= chr(($buffer >> $bits) & 255);
            }

            $buffer &= (1 << $bits) - 1;
        }

        $counter = intdiv($timestamp, 30);
        $message = pack('N2', intdiv($counter, 4294967296), $counter & 0xffffffff);
        $hash = hash_hmac('sha1', $message, $key, true);
        $offset = ord($hash[19]) & 15;
        $number = unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff;

        return str_pad((string)($number % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    public static function counter(string $secret, string $code, int $timestamp, int $last = -1): ?int
    {
        if (!preg_match('/^[0-9]{6}$/D', $code)) {
            return null;
        }

        $current = intdiv($timestamp, 30);

        foreach ([$current, $current - 1, $current + 1] as $counter) {
            if ($counter >= 0 && $counter > $last && hash_equals(self::code($secret, $counter * 30), $code)) {
                return $counter;
            }
        }

        return null;
    }
}
