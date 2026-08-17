<?php

namespace {
    $runtimeDirectory = getenv(
        'ACCESS_GUARD_TEST_RUNTIME'
    );

    $repositoryDirectory = getenv(
        'ACCESS_GUARD_TEST_REPOSITORY'
    );

    if (
        !is_string($runtimeDirectory) ||
        $runtimeDirectory === '' ||
        !is_string($repositoryDirectory) ||
        $repositoryDirectory === ''
    ) {
        http_response_code(500);
        exit('テスト環境が設定されていません。');
    }

    define('BASE_PATH', $runtimeDirectory);
    define('BASE_URL', '');

    session_save_path(
        $runtimeDirectory . '/sessions'
    );

    session_start();

    function url(string $path = ''): string
    {
        $path = trim($path, '/');

        return $path === ''
            ? '/'
            : '/' . $path;
    }

    function redirect_to(string $path): void
    {
        header('Location: ' . url($path));
        exit;
    }

    function e(?string $value): string
    {
        return htmlspecialchars(
            (string)$value,
            ENT_QUOTES,
            'UTF-8'
        );
    }
}

namespace app\Core {
    class Controller
    {
    }

    class Auth
    {
        public static function check(): bool
        {
            return isset($_SESSION['user']);
        }

        public static function login(array $user): void
        {
            session_regenerate_id(true);

            $_SESSION['user'] = [
                'id' => $user['id'],
                'username' => $user['username'],
                'name' => $user['name'],
                'email' => $user['email'],
                'role' => $user['role'],
            ];
        }

        public static function logout(): void
        {
            unset($_SESSION['user']);
            session_regenerate_id(true);
        }

        public static function requireLogin(): void
        {
            if (!self::check()) {
                \redirect_to('admin/login');
            }
        }
    }

    class Csrf
    {
        public static function token(): string
        {
            if (empty($_SESSION['_csrf_token'])) {
                $_SESSION['_csrf_token'] = bin2hex(
                    random_bytes(32)
                );
            }

            return $_SESSION['_csrf_token'];
        }

        public static function requireValid(
            ?string $token
        ): void {
            if (
                !empty($_SESSION['_csrf_token']) &&
                !empty($token) &&
                hash_equals(
                    $_SESSION['_csrf_token'],
                    $token
                )
            ) {
                return;
            }

            http_response_code(419);
            exit('不正なリクエストです。');
        }

        public static function regenerate(): void
        {
            $_SESSION['_csrf_token'] = bin2hex(
                random_bytes(32)
            );
        }
    }

    class Router
    {
        private array $routes = [];

        public function get(
            string $path,
            string $action
        ): void {
            $this->routes['GET'][$path] = $action;
        }

        public function post(
            string $path,
            string $action
        ): void {
            $this->routes['POST'][$path] = $action;
        }

        public function dispatch(): void
        {
            $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
            $uri = parse_url(
                $_SERVER['REQUEST_URI'] ?? '/',
                PHP_URL_PATH
            );

            if (!is_string($uri)) {
                $uri = '/';
            }

            $uri = rtrim($uri, '/');

            if ($uri === '') {
                $uri = '/';
            }

            $action =
                $this->routes[$method][$uri] ?? null;

            if (!is_string($action)) {
                http_response_code(404);
                echo '404 Not Found';
                return;
            }

            [$controllerName, $methodName] =
                explode('@', $action);

            $controller = new $controllerName();
            $controller->{$methodName}();
        }
    }
}

namespace app\Models {
    class User
    {
        public static function findByUsername(
            string $username
        ): ?array {
            if ($username !== 'admin') {
                return null;
            }

            return [
                'id' => 1,
                'username' => 'admin',
                'name' => '管理者',
                'email' => 'admin@example.com',
                'role' => 'administrator',
                'password_hash' => password_hash(
                    'correct-password',
                    PASSWORD_DEFAULT
                ),
            ];
        }
    }
}

namespace TestSupport {
    use app\Core\Auth;
    use app\Models\User;

    class StandardAuthController
    {
        public function login(): void
        {
            if (Auth::check()) {
                \redirect_to('admin');
            }

            $this->render();
        }

        public function authenticate(): void
        {
            $username = trim(
                (string)($_POST['username'] ?? '')
            );

            $password =
                (string)($_POST['password'] ?? '');

            $user = User::findByUsername($username);

            if (
                !$user ||
                !password_verify(
                    $password,
                    $user['password_hash']
                )
            ) {
                $this->render(
                    'ユーザー名またはパスワードが正しくありません。',
                    $username
                );
                return;
            }

            Auth::login($user);
            \redirect_to('admin');
        }

        public function logout(): void
        {
            Auth::logout();
            \redirect_to('admin/login');
        }

        private function render(
            ?string $error = null,
            string $username = ''
        ): void {
            if ($error !== null) {
                echo '<p class="error-message">'
                    . \e($error)
                    . '</p>';
            }

            echo '<form method="post" action="/admin/login">'
                . '<label for="username">ユーザー名</label>'
                . '<input type="text" id="username" '
                . 'name="username" value="'
                . \e($username)
                . '">'
                . '<input type="password" name="password">'
                . '</form>';
        }
    }

    class AdminController
    {
        public function index(): void
        {
            Auth::requireLogin();
            echo 'ADMIN OK';
        }
    }
}

namespace {
    use app\Core\Router;

    $router = new Router();

    $router->get(
        '/admin/login',
        TestSupport\StandardAuthController::class . '@login'
    );

    $router->post(
        '/admin/login',
        TestSupport\StandardAuthController::class . '@authenticate'
    );

    $router->get(
        '/admin/logout',
        TestSupport\StandardAuthController::class . '@logout'
    );

    $router->get(
        '/admin',
        TestSupport\AdminController::class . '@index'
    );

    $router->get(
        '/admin/posts',
        TestSupport\AdminController::class . '@index'
    );

    $testConfigurationPath =
        BASE_PATH . '/test-config.json';

    $testConfiguration = [];

    if (is_file($testConfigurationPath)) {
        $decoded = json_decode(
            (string)file_get_contents(
                $testConfigurationPath
            ),
            true
        );

        if (is_array($decoded)) {
            $testConfiguration = $decoded;
        }
    }

    if (!empty($testConfiguration['extension_enabled'])) {
        $includeFiles = [
            '/includes/Settings.php',
            '/includes/IpRules.php',
            '/includes/LoginUrl.php',
            '/includes/LoginLock.php',
            '/includes/FailOnce.php',
            '/includes/AccessControl.php',
        ];

        foreach ($includeFiles as $includeFile) {
            require_once $repositoryDirectory
                . $includeFile;
        }

        NexaPressAccessGuard\AccessControl::boot(
            $router
        );
    }

    $router->dispatch();
}
