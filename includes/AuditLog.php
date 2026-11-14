<?php

namespace NexaPressAccessGuard;

use Throwable;

class AuditLog
{
    private const ROUTINE_EVENTS = [
        'access_denied', 'login_failure', 'login_locked', 'mfa_failure',
        'login_success', 'logout', 'recovery_used', 'mfa_management_failure',
    ];

    public static function path(): string
    {
        return BASE_PATH . '/storage/extensions/access-guard/audit.json';
    }

    public static function record(string $event, string $username = '', array $details = [], ?array $notifications = null): void
    {
        try {
            $settings = Settings::all();
            $username = substr($username !== '' ? $username : (string)($_SESSION['user']['username'] ?? ''), 0, 128);
            $username = json_decode(json_encode($username, JSON_INVALID_UTF8_SUBSTITUTE), true);
            $entry = [
                'time' => time(),
                'event' => $event,
                'username' => $username,
                'ip' => IpRules::currentIp(),
                'details' => array_intersect_key($details, array_flip(['section', 'disabled', 'source', 'reason'])),
            ];

            $failures = JsonStorage::update(self::path(), [], [self::class, 'validate'],
                static function (array &$data) use ($entry, $settings): int {
                    $data[] = $entry;
                    $cutoff = time() - $settings['audit']['retention_days'] * 86400;
                    $data = array_values(array_filter($data, static fn(array $row): bool => $row['time'] >= $cutoff));
                    $data = array_slice(self::capRoutineEvents($data, 1000), -2000);

                    return count(array_filter($data, static fn(array $row): bool =>
                        $row['time'] >= time() - 300 && in_array($row['event'], ['login_failure', 'mfa_failure'], true)));
                });

            Notification::consider($entry, $failures, $notifications ?? $settings['notifications']);
        } catch (Throwable $exception) {
            error_log('Access Guard: 監査ログまたは通知を保存できません。');
        }
    }

    public static function recent(): array
    {
        $cutoff = time() - Settings::get('audit')['retention_days'] * 86400;
        $data = JsonStorage::read(self::path(), [], [self::class, 'validate']);
        $data = array_filter($data, static fn(array $row): bool => $row['time'] >= $cutoff);

        return array_reverse(array_slice(self::capRoutineEvents($data, 50), -100));
    }

    private static function capRoutineEvents(array $data, int $maximum): array
    {
        $indices = array_keys(array_filter($data, static fn(array $row): bool =>
            in_array($row['event'], self::ROUTINE_EVENTS, true)));
        foreach (array_slice($indices, 0, max(0, count($indices) - $maximum)) as $index) {
            unset($data[$index]);
        }

        return array_values($data);
    }

    public static function validate(array $data): array
    {
        foreach ($data as $entry) {
            if (!is_array($entry) || !isset($entry['time'], $entry['event'], $entry['ip'], $entry['username'], $entry['details']) ||
                !is_int($entry['time']) || !is_string($entry['event']) || !is_string($entry['ip']) ||
                !is_string($entry['username']) || !is_array($entry['details'])) {
                throw new StorageException('監査ログが破損しています。');
            }
        }

        return $data;
    }
}
