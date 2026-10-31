<?php

/*
 * Access GuardのHTTP回帰テスト
 */

$repositoryDirectory = dirname(__DIR__);
$runtimeDirectory = sys_get_temp_dir()
    . '/nexapress-access-guard-tests-'
    . bin2hex(random_bytes(6));

$serverLog = $runtimeDirectory . '/server.log';
$routerFile = __DIR__ . '/http/index.php';

$directories = [
    $runtimeDirectory,
    $runtimeDirectory . '/sessions',
    $runtimeDirectory . '/app/Views/admin',
    $runtimeDirectory
        . '/storage/extensions/access-guard',
];

foreach ($directories as $directory) {
    if (
        !is_dir($directory) &&
        !mkdir($directory, 0777, true)
    ) {
        throw new RuntimeException(
            'テスト用フォルダを作成できません: '
            . $directory
        );
    }
}

file_put_contents(
    $runtimeDirectory
        . '/app/Views/admin/login-layout.php',
    '<!doctype html><html><body>'
        . '<?= $content ?>'
        . '</body></html>'
);

$socket = stream_socket_server(
    'tcp://127.0.0.1:0',
    $errorNumber,
    $errorMessage
);

if ($socket === false) {
    throw new RuntimeException(
        'テスト用ポートを確保できません: '
        . $errorMessage
    );
}

$socketName = stream_socket_get_name(
    $socket,
    false
);

fclose($socket);

if (!is_string($socketName)) {
    throw new RuntimeException(
        'テスト用ポートを取得できません。'
    );
}

$port = (int)substr(
    $socketName,
    strrpos($socketName, ':') + 1
);

$environment = getenv();
$environment['ACCESS_GUARD_TEST_RUNTIME'] =
    $runtimeDirectory;
$environment['ACCESS_GUARD_TEST_REPOSITORY'] =
    $repositoryDirectory;

$process = proc_open(
    [
        PHP_BINARY,
        '-d',
        'display_errors=0',
        '-d',
        'log_errors=1',
        '-S',
        '127.0.0.1:' . $port,
        $routerFile,
    ],
    [
        0 => ['pipe', 'r'],
        1 => ['file', $serverLog, 'a'],
        2 => ['file', $serverLog, 'a'],
    ],
    $pipes,
    $repositoryDirectory,
    $environment
);

if (!is_resource($process)) {
    throw new RuntimeException(
        'PHPテストサーバーを起動できません。'
    );
}

fclose($pipes[0]);

$baseUrl = 'http://127.0.0.1:' . $port;
$assertions = 0;
$failures = [];

function writeJson(
    string $path,
    array $data
): void {
    $json = json_encode(
        $data,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES |
        JSON_PRETTY_PRINT |
        JSON_THROW_ON_ERROR
    );

    file_put_contents($path, $json);
}

function defaultSettings(): array
{
    return [
        'login_page_access' => [
            'enabled' => false,
        ],
        'admin_page_access' => [
            'enabled' => false,
        ],
        'login_url' => [
            'enabled' => true,
            'slug' => 'secure-entry',
        ],
        'login_lock' => [
            'enabled' => false,
            'attempts' => 5,
            'duration' => 30,
        ],
        'fail_once' => [
            'enabled' => false,
            'count' => 1,
        ],
        'allowed_ips' => [],
        'denied_ips' => [],
    ];
}

function configureExtension(
    string $runtimeDirectory,
    bool $enabled,
    array $settings = []
): void {
    writeJson(
        $runtimeDirectory . '/test-config.json',
        ['extension_enabled' => $enabled]
    );

    $settings = array_replace_recursive(
        defaultSettings(),
        $settings
    );

    writeJson(
        $runtimeDirectory
            . '/storage/extensions/access-guard/settings.json',
        $settings
    );

    foreach (
        ['login-locks.json', 'login-locks.json.bak', 'fail-once.json', 'settings.json.bak', 'two-factor.json', 'two-factor.json.bak']
        as $fileName
    ) {
        $path = $runtimeDirectory
            . '/storage/extensions/access-guard/'
            . $fileName;

        if (is_file($path)) {
            unlink($path);
        }
    }
}

function newClient()
{
    $client = curl_init();

    curl_setopt_array($client, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_COOKIEFILE => '',
        CURLOPT_TIMEOUT => 10,
    ]);

    return $client;
}

function request(
    $client,
    string $baseUrl,
    string $method,
    string $path,
    array $postData = []
): array {
    curl_setopt(
        $client,
        CURLOPT_URL,
        $baseUrl . $path
    );

    if ($method === 'POST') {
        curl_setopt(
            $client,
            CURLOPT_CUSTOMREQUEST,
            'POST'
        );
        curl_setopt($client, CURLOPT_POST, true);
        curl_setopt(
            $client,
            CURLOPT_POSTFIELDS,
            http_build_query($postData)
        );
    } else {
        curl_setopt($client, CURLOPT_POST, false);
        curl_setopt(
            $client,
            CURLOPT_CUSTOMREQUEST,
            'GET'
        );
        curl_setopt($client, CURLOPT_HTTPGET, true);
        curl_setopt($client, CURLOPT_POSTFIELDS, null);
    }

    $response = curl_exec($client);

    if ($response === false) {
        throw new RuntimeException(
            'HTTPリクエストに失敗しました: '
            . curl_error($client)
        );
    }

    $headerSize = (int)curl_getinfo(
        $client,
        CURLINFO_HEADER_SIZE
    );

    return [
        'status' => (int)curl_getinfo(
            $client,
            CURLINFO_RESPONSE_CODE
        ),
        'headers' => substr($response, 0, $headerSize),
        'body' => substr($response, $headerSize),
    ];
}

function csrfToken(string $body): string
{
    if (
        !preg_match(
            '/name="_csrf_token"\s+value="([^"]+)"/',
            $body,
            $matches
        )
    ) {
        throw new RuntimeException(
            'CSRFトークンがログイン画面にありません。'
        );
    }

    return html_entity_decode(
        $matches[1],
        ENT_QUOTES,
        'UTF-8'
    );
}

function location(array $response): ?string
{
    if (
        preg_match(
            '/^Location:\s*(.+)$/mi',
            $response['headers'],
            $matches
        )
    ) {
        return trim($matches[1]);
    }

    return null;
}

function assertSameValue(
    mixed $expected,
    mixed $actual,
    string $message
): void {
    global $assertions, $failures;

    $assertions++;

    if ($expected !== $actual) {
        $failures[] = $message
            . ' (expected: '
            . var_export($expected, true)
            . ', actual: '
            . var_export($actual, true)
            . ')';
    }
}

function assertContainsText(
    string $needle,
    string $haystack,
    string $message
): void {
    global $assertions, $failures;

    $assertions++;

    if (!str_contains($haystack, $needle)) {
        $failures[] = $message
            . ' (missing: '
            . $needle
            . ')';
    }
}

function assertNotContainsText(
    string $needle,
    string $haystack,
    string $message
): void {
    global $assertions, $failures;

    $assertions++;

    if (str_contains($haystack, $needle)) {
        $failures[] = $message
            . ' (unexpected: '
            . $needle
            . ')';
    }
}

try {
    $ready = false;

    for ($attempt = 0; $attempt < 50; $attempt++) {
        $client = newClient();

        try {
            $response = request(
                $client,
                $baseUrl,
                'GET',
                '/not-ready'
            );

            $ready = $response['status'] > 0;
        } catch (RuntimeException) {
            usleep(100000);
        } finally {
            curl_close($client);
        }

        if ($ready) {
            break;
        }
    }

    if (!$ready) {
        throw new RuntimeException(
            'PHPテストサーバーが応答しません。'
        );
    }

    /* Access Guard無効時の標準ログイン */
    configureExtension(
        $runtimeDirectory,
        false
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/admin/login'
    );

    assertSameValue(
        200,
        $response['status'],
        'Access Guard無効時の標準ログイン画面'
    );
    assertContainsText(
        'name="username"',
        $response['body'],
        '標準ログインはユーザー名入力'
    );
    assertNotContainsText(
        'name="email"',
        $response['body'],
        '標準ログインにメール入力がない'
    );

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/admin/login',
        [
            'username' => 'admin',
            'password' => 'correct-password',
        ]
    );

    assertSameValue(
        302,
        $response['status'],
        '標準ログイン成功'
    );
    assertSameValue(
        '/admin',
        location($response),
        '標準ログイン後の遷移先'
    );
    curl_close($client);

    /* 変更後URLの表示・認証・旧URL・管理画面誘導 */
    configureExtension(
        $runtimeDirectory,
        true
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/secure-entry'
    );
    $token = csrfToken($response['body']);

    assertSameValue(
        200,
        $response['status'],
        '変更後ログイン画面'
    );
    assertContainsText(
        'ユーザー名',
        $response['body'],
        '変更後ログインのラベル'
    );
    assertContainsText(
        'name="username"',
        $response['body'],
        '変更後ログインのユーザー名入力'
    );
    assertNotContainsText(
        'name="email"',
        $response['body'],
        '変更後ログインにメール入力がない'
    );

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/secure-entry',
        [
            '_csrf_token' => $token,
            'username' => 'admin',
            'email' => 'unused@example.invalid',
            'password' => 'correct-password',
        ]
    );

    assertSameValue(
        302,
        $response['status'],
        '変更後URLで正しいユーザー名によりログイン'
    );
    assertSameValue(
        '/admin',
        location($response),
        '変更後URLのログイン後遷移先'
    );

    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/admin'
    );
    assertSameValue(
        200,
        $response['status'],
        'ログイン済み管理画面アクセス'
    );
    assertContainsText(
        'ADMIN OK',
        $response['body'],
        'ログイン済み管理画面の内容'
    );

    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/admin/logout'
    );
    assertSameValue(
        302,
        $response['status'],
        'ログアウト応答'
    );
    assertSameValue(
        '/secure-entry',
        location($response),
        'ログアウト後は変更後URLへ遷移'
    );
    curl_close($client);

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/admin/login'
    );
    assertSameValue(
        404,
        $response['status'],
        '変更中の旧ログインGETは404'
    );

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/admin/login',
        []
    );
    assertSameValue(
        404,
        $response['status'],
        '変更中の旧ログインPOSTは404'
    );

    foreach (['/admin', '/admin/posts'] as $adminPath) {
        $response = request(
            $client,
            $baseUrl,
            'GET',
            $adminPath
        );
        assertSameValue(
            302,
            $response['status'],
            '未ログイン管理画面からの誘導: '
                . $adminPath
        );
        assertSameValue(
            '/secure-entry',
            location($response),
            '未ログイン管理画面の遷移先: '
                . $adminPath
        );
    }
    curl_close($client);

    /* 通常の入力・認証エラー */
    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/secure-entry'
    );
    $token = csrfToken($response['body']);

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/secure-entry',
        [
            '_csrf_token' => $token,
            'username' => '',
            'password' => '',
        ]
    );
    assertSameValue(
        200,
        $response['status'],
        '空欄ログインは500にならない'
    );
    assertContainsText(
        'ユーザー名とパスワードを入力してください。',
        $response['body'],
        '空欄ログインのエラーメッセージ'
    );

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/secure-entry',
        [
            '_csrf_token' => $token,
            'username' => 'wrong-user',
            'password' => 'wrong-password',
        ]
    );
    assertSameValue(
        200,
        $response['status'],
        '誤った認証情報は500にならない'
    );
    assertContainsText(
        'ログイン情報が正しくありません。',
        $response['body'],
        '誤った認証情報のエラー'
    );
    curl_close($client);

    /* CSRF */
    $client = newClient();
    request(
        $client,
        $baseUrl,
        'GET',
        '/secure-entry'
    );
    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/secure-entry',
        [
            '_csrf_token' => 'invalid-token',
            'username' => 'admin',
            'password' => 'correct-password',
        ]
    );
    assertSameValue(
        419,
        $response['status'],
        '不正CSRFトークンを拒否'
    );
    curl_close($client);

    /* ログインロック */
    configureExtension(
        $runtimeDirectory,
        true,
        [
            'login_lock' => [
                'enabled' => true,
                'attempts' => 2,
                'duration' => 30,
            ],
        ]
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/secure-entry'
    );
    $token = csrfToken($response['body']);

    for ($attempt = 1; $attempt <= 2; $attempt++) {
        $response = request(
            $client,
            $baseUrl,
            'POST',
            '/secure-entry',
            [
                '_csrf_token' => $token,
                'username' => 'admin',
                'password' => 'wrong-password',
            ]
        );
    }

    assertContainsText(
        '一時的にロックしました。',
        $response['body'],
        '上限到達時にログインをロック'
    );

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/secure-entry',
        [
            '_csrf_token' => $token,
            'username' => 'admin',
            'password' => 'correct-password',
        ]
    );
    assertSameValue(
        200,
        $response['status'],
        'ロック中は正しい認証情報でも拒否'
    );
    assertContainsText(
        'ログインが一時的にロックされています。',
        $response['body'],
        'ロック中のエラーメッセージ'
    );
    curl_close($client);

    /* FailOnce */
    configureExtension(
        $runtimeDirectory,
        true,
        [
            'fail_once' => [
                'enabled' => true,
                'count' => 1,
            ],
        ]
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/secure-entry'
    );
    $token = csrfToken($response['body']);

    $loginData = [
        '_csrf_token' => $token,
        'username' => 'admin',
        'password' => 'correct-password',
    ];

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/secure-entry',
        $loginData
    );
    assertSameValue(
        200,
        $response['status'],
        'FailOnceの初回拒否'
    );
    assertContainsText(
        'ログイン情報が正しくありません。',
        $response['body'],
        'FailOnceの初回エラー'
    );

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/secure-entry',
        $loginData
    );
    assertSameValue(
        302,
        $response['status'],
        'FailOnce完了後はログイン成功'
    );
    curl_close($client);

    /* 許可IPではFailOnceを適用しない */
    configureExtension(
        $runtimeDirectory,
        true,
        [
            'fail_once' => [
                'enabled' => true,
                'count' => 1,
            ],
            'allowed_ips' => ['127.0.0.1'],
        ]
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/secure-entry'
    );
    $token = csrfToken($response['body']);

    $response = request(
        $client,
        $baseUrl,
        'POST',
        '/secure-entry',
        [
            '_csrf_token' => $token,
            'username' => 'admin',
            'password' => 'correct-password',
        ]
    );
    assertSameValue(
        302,
        $response['status'],
        '許可IPはFailOnce対象外'
    );
    curl_close($client);

    /* ログインページ・管理ページの許可IP制限 */
    configureExtension(
        $runtimeDirectory,
        true,
        [
            'login_page_access' => [
                'enabled' => true,
            ],
        ]
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/secure-entry'
    );
    assertSameValue(
        403,
        $response['status'],
        '未許可IPのログインページを拒否'
    );
    curl_close($client);

    configureExtension(
        $runtimeDirectory,
        true,
        [
            'login_page_access' => [
                'enabled' => true,
            ],
            'allowed_ips' => ['127.0.0.1'],
        ]
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/secure-entry'
    );
    assertSameValue(
        200,
        $response['status'],
        '許可IPのログインページアクセス'
    );
    curl_close($client);

    configureExtension(
        $runtimeDirectory,
        true,
        [
            'admin_page_access' => [
                'enabled' => true,
            ],
        ]
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/admin'
    );
    assertSameValue(
        403,
        $response['status'],
        '未許可IPの管理ページを拒否'
    );
    curl_close($client);

    configureExtension(
        $runtimeDirectory,
        true,
        [
            'admin_page_access' => [
                'enabled' => true,
            ],
            'allowed_ips' => ['127.0.0.1'],
        ]
    );

    $client = newClient();
    $response = request(
        $client,
        $baseUrl,
        'GET',
        '/admin'
    );
    assertSameValue(
        302,
        $response['status'],
        '許可IPの未ログイン管理画面はログインへ誘導'
    );
    assertSameValue(
        '/secure-entry',
        location($response),
        '許可IPの管理画面から変更後URLへ誘導'
    );
    curl_close($client);

    /* 拒否IPは常に優先 */
    configureExtension(
        $runtimeDirectory,
        true,
        [
            'allowed_ips' => ['127.0.0.1'],
            'denied_ips' => ['127.0.0.1'],
        ]
    );

    $client = newClient();

    foreach (['/secure-entry', '/admin'] as $path) {
        $response = request(
            $client,
            $baseUrl,
            'GET',
            $path
        );
        assertSameValue(
            403,
            $response['status'],
            '拒否IPを優先: ' . $path
        );
    }

    curl_close($client);

    /* 設定保存の全9経路で管理権限・CSRFを確認する。 */
    configureExtension($runtimeDirectory, true);
    $settingsPath = $runtimeDirectory . '/storage/extensions/access-guard/settings.json';
    $settingsBase = '/admin/extensions/access-guard/settings/';
    $settingsActions = [
        'login-access', 'admin-access', 'login-url', 'login-lock', 'fail-once',
        'allowed-ip/add', 'allowed-ip/remove', 'denied-ip/add', 'denied-ip/remove', 'trusted-proxy', 'monitoring',
    ];
    $form = [
        'enabled' => '1', 'slug' => 'secure-entry', 'attempts' => '3',
        'duration' => '15', 'count' => '1', 'ip' => '192.0.2.222',
    ];

    foreach (['editor', 'admin'] as $username) {
        $client = newClient();
        $response = request($client, $baseUrl, 'GET', '/secure-entry');
        $response = request($client, $baseUrl, 'POST', '/secure-entry', [
            '_csrf_token' => csrfToken($response['body']),
            'username' => $username,
            'password' => 'correct-password',
        ]);
        assertSameValue(302, $response['status'], $username . 'のログイン');
        $response = request($client, $baseUrl, 'GET', '/admin');
        $token = csrfToken($response['body']);
        $before = file_get_contents($settingsPath);

        foreach ($settingsActions as $action) {
            $response = request($client, $baseUrl, 'POST', $settingsBase . $action, [
                '_csrf_token' => $username === 'editor' ? $token : 'invalid-token',
            ] + $form);
            assertSameValue($username === 'editor' ? 403 : 419, $response['status'],
                $username . 'の不正な設定保存を拒否: ' . $action);
        }

        assertSameValue($before, file_get_contents($settingsPath), '拒否後は設定が変わらない: ' . $username);
        $response = request($client, $baseUrl, 'GET', '/admin/extensions/access-guard/dashboard');
        assertSameValue($username === 'editor' ? 403 : 200, $response['status'], '設定画面の閲覧権限: ' . $username);

        if ($username === 'admin') {
            $validForms = [
                'allowed-ip/add' => ['ip' => '::ffff:127.0.0.1'],
                'login-access' => ['enabled' => '1'],
                'admin-access' => ['enabled' => '1'],
                'login-url' => ['enabled' => '1', 'slug' => 'secure-entry'],
                'login-lock' => ['enabled' => '1', 'attempts' => '5', 'duration' => '30'],
                'fail-once' => ['enabled' => '1', 'count' => '1'],
                'denied-ip/add' => ['ip' => '2001:0DB8:0000:0000:0000:0000:0000:0001'],
                'denied-ip/remove' => ['ip' => '2001:db8::1'],
            ];

            foreach ($validForms as $action => $values) {
                $response = request($client, $baseUrl, 'POST', $settingsBase . $action,
                    ['_csrf_token' => $token] + $values);
                assertSameValue(302, $response['status'], '管理者の保存成功: ' . $action);
            }

            $settings = json_decode(file_get_contents($settingsPath), true);
            assertSameValue(['127.0.0.1'], $settings['allowed_ips'], '登録時にIPv4射影表記を正規化');
            assertSameValue([], $settings['denied_ips'], 'IPv6の別表記から拒否IPを削除');
            assertSameValue(true, $settings['admin_page_access']['enabled'], '管理者による保護設定の有効化');

            foreach (['denied-ip/add', 'allowed-ip/remove'] as $action) {
                $response = request($client, $baseUrl, 'POST', $settingsBase . $action, [
                    '_csrf_token' => $token, 'ip' => '::ffff:127.0.0.1',
                ]);
                assertSameValue(302, $response['status'], '自己締め出しをエラー通知へ戻す: ' . $action);
            }

            $settings = json_decode(file_get_contents($settingsPath), true);
            assertSameValue(['127.0.0.1'], $settings['allowed_ips'], '別表記で自分の許可IPを削除できない');
            assertSameValue([], $settings['denied_ips'], '別表記で自分を拒否IPに登録できない');

            request($client, $baseUrl, 'POST', $settingsBase . 'login-access', ['_csrf_token' => $token]);
            request($client, $baseUrl, 'POST', $settingsBase . 'admin-access', ['_csrf_token' => $token]);
            $response = request($client, $baseUrl, 'POST', $settingsBase . 'allowed-ip/remove', [
                '_csrf_token' => $token, 'ip' => '::ffff:127.0.0.1',
            ]);
            assertSameValue(302, $response['status'], '制限解除後の許可IP削除');
            $settings = json_decode(file_get_contents($settingsPath), true);
            assertSameValue([], $settings['allowed_ips'], '制限解除後は許可IPを削除できる');
        }

        curl_close($client);
    }

    /* 設定JSONの破損・型不正・消失はいずれも保護解除せず503。 */
    configureExtension($runtimeDirectory, true);
    $goodSettings = file_get_contents($settingsPath);
    $client = newClient();

    foreach (['{', '{}', '{"admin_page_access":{"enabled":false}}'] as $invalid) {
        file_put_contents($settingsPath, $invalid);

        foreach (['/admin', '/secure-entry'] as $path) {
            $response = request($client, $baseUrl, 'GET', $path);
            assertSameValue(503, $response['status'], '設定異常時は停止: ' . $path);
            assertNotContainsText('name="password"', $response['body'], '異常時にログイン画面を公開しない');
        }
    }

    file_put_contents($settingsPath . '.bak', $goodSettings);
    unlink($settingsPath);
    $response = request($client, $baseUrl, 'GET', '/admin');
    assertSameValue(503, $response['status'], '既存設定の消失も503');
    file_put_contents($settingsPath, $goodSettings);
    $response = request($client, $baseUrl, 'GET', '/secure-entry');
    assertSameValue(200, $response['status'], '復旧後にログイン画面へ戻れる');

    /* アカウントのロックは新しいIPのHTTPリクエストにも適用する。 */
    configureExtension($runtimeDirectory, true, ['login_lock' => ['enabled' => true]]);
    $response = request($client, $baseUrl, 'GET', '/secure-entry');
    $token = csrfToken($response['body']);
    $locksPath = $runtimeDirectory . '/storage/extensions/access-guard/login-locks.json';
    writeJson($locksPath, [
        'account:' . hash('sha256', 'admin') => [
            'count' => 5, 'updated_at' => time(), 'locked_until' => time() + 600,
            'next_attempt_at' => 0,
        ],
    ]);
    $response = request($client, $baseUrl, 'POST', '/secure-entry', [
        '_csrf_token' => $token, 'username' => 'ADMIN', 'password' => 'correct-password',
    ]);
    assertSameValue(200, $response['status'], 'IPの履歴がなくてもアカウントロックを適用');
    assertContainsText('一時的にロックされています', $response['body'], '正しい認証情報でもロックを維持');
    assertContainsText('Retry-After:', $response['headers'], '待機時間をヘッダーで通知');

    file_put_contents($locksPath, '{');
    $response = request($client, $baseUrl, 'POST', '/secure-entry', [
        '_csrf_token' => $token, 'username' => 'admin', 'password' => 'correct-password',
    ]);
    assertSameValue(503, $response['status'], 'ロック情報破損時は認証せず503');
    curl_close($client);
    require __DIR__ . '/feature-http.php';
} finally {
    proc_terminate($process);
    proc_close($process);
}

if ($failures !== []) {
    fwrite(
        STDERR,
        "FAIL: {$assertions} assertions, "
            . count($failures)
            . " failures\n"
    );

    foreach ($failures as $failure) {
        fwrite(STDERR, '- ' . $failure . "\n");
    }

    if (is_file($serverLog)) {
        fwrite(
            STDERR,
            "--- PHP server log ---\n"
                . file_get_contents($serverLog)
                . "--- end log ---\n"
        );
    }

    exit(1);
}

echo "PASS: {$assertions} assertions\n";
