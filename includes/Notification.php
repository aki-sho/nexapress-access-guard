<?php

namespace NexaPressAccessGuard;

class Notification
{
    public static function consider(array $entry, int $failures, array $settings): void
    {
        if (!$settings['enabled']) {
            return;
        }

        $critical = in_array($entry['event'], ['mfa_disabled', 'recovery_used', 'cli_recovery'], true) ||
            ($entry['event'] === 'settings_changed' && !empty($entry['details']['disabled']));
        $burst = in_array($entry['event'], ['login_failure', 'mfa_failure'], true) &&
            $failures >= $settings['failure_threshold'];

        if (!$critical && !$burst) {
            return;
        }

        $key = $critical ? $entry['event'] . ':' . ($entry['details']['section'] ?? '') : 'failure_burst';
        $send = JsonStorage::update(BASE_PATH . '/storage/extensions/access-guard/notifications.json', [],
            static function (array $data): array {
                foreach ($data as $time) {
                    if (!is_int($time) || $time < 0) {
                        throw new StorageException('通知履歴が正しくありません。');
                    }
                }

                return $data;
            },
            static function (array &$data) use ($key): bool {
                if (($data[$key] ?? 0) > time() - 300) {
                    return false;
                }

                $data[$key] = time();
                return true;
            });

        if (!$send) {
            return;
        }

        $body = "NexaPress Access Guard\n"
            . 'UTC: ' . gmdate('Y-m-d H:i:s', $entry['time']) . "\n"
            . 'Event: ' . $entry['event'] . "\n"
            . 'User: ' . $entry['username'] . "\n"
            . 'IP: ' . $entry['ip'] . "\n"
            . 'Failures in 5 minutes: ' . $failures . "\n";

        if (!@mail($settings['email'], 'NexaPress Access Guard security alert', $body, "Content-Type: text/plain; charset=UTF-8")) {
            error_log('Access Guard: 異常通知のメール送信に失敗しました。PHPのメール設定を確認してください。');
            AuditLog::record('notification_failed');
        }
    }
}
