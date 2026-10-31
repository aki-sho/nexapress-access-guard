<?php

/* 並行書き込みテスト専用。Webからは実行しない。 */
if (PHP_SAPI !== 'cli' || $argc !== 4) {
    exit(1);
}

define('BASE_PATH', $argv[1]);
require dirname(__DIR__) . '/includes/JsonStorage.php';
require dirname(__DIR__) . '/includes/IpRules.php';
require dirname(__DIR__) . '/includes/Settings.php';
require dirname(__DIR__) . '/includes/LoginLock.php';

for ($iteration = 1; $iteration <= 8; $iteration++) {
    if ($argv[2] === 'settings') {
        \NexaPressAccessGuard\Settings::addIp('allowed_ips', '192.0.2.' . ((int)$argv[3] * 8 + $iteration));
    } else {
        \NexaPressAccessGuard\LoginLock::recordFailure('198.51.100.' . $argv[3], 'parallel-account');
    }
}
