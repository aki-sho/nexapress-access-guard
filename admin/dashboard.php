<?php

/*
 * 設定情報を取得
 */
$settings =
    \NexaPressAccessGuard\Settings::all();

$notice =
    \NexaPressAccessGuard\Settings::pullNotice();

$csrfToken =
    \app\Core\Csrf::token();

$currentIp =
    \NexaPressAccessGuard\IpRules::currentIp();

$loginAccess =
    $settings['login_page_access'];

$adminAccess =
    $settings['admin_page_access'];

$loginUrl =
    $settings['login_url'];

$loginLock =
    $settings['login_lock'];

$failOnce =
    $settings['fail_once'];

$allowedIps =
    $settings['allowed_ips'];

$deniedIps =
    $settings['denied_ips'];

$checked = static function (
    mixed $value
): string {
    return !empty($value)
        ? ' checked'
        : '';
};

$selected = static function (
    int $value,
    mixed $current
): string {
    return $value === (int)$current
        ? ' selected'
        : '';
};
?>

<div class="access-guard">
    <div class="access-guard-header">
        <div>
            <h1>アクセスガード</h1>

            <p>
                ログインページと管理画面への
                アクセスを保護します。
            </p>
        </div>

        <div class="access-guard-current-ip">
            <span>現在のIP</span>

            <strong>
                <?= e(
                    $currentIp !== ''
                        ? $currentIp
                        : '取得できません'
                ) ?>
            </strong>
        </div>
    </div>

    <?php if ($notice !== null): ?>
        <?php
        $noticeType =
            ($notice['type'] ?? '') === 'error'
                ? 'error'
                : 'success';
        ?>

        <div class="access-guard-notice access-guard-notice-<?= e($noticeType) ?>">
            <?= e(
                (string)($notice['message'] ?? '')
            ) ?>
        </div>
    <?php endif; ?>

    <div class="access-guard-grid">
        <!-- ログインページアクセス制限 -->
        <section class="access-guard-card">
            <h2>ログインページアクセス制限</h2>

            <p>
                許可IPだけがログインページへ
                アクセスできます。
            </p>

            <form
                method="post"
                action="<?= url(
                    'admin/extensions/access-guard/settings/login-access'
                ) ?>"
            >
                <input
                    type="hidden"
                    name="_csrf_token"
                    value="<?= e($csrfToken) ?>"
                >

                <label class="access-guard-switch-row">
                    <input
                        type="checkbox"
                        name="enabled"
                        value="1"
                        <?= $checked(
                            $loginAccess['enabled'] ?? false
                        ) ?>
                    >

                    <span>この機能を有効にする</span>
                </label>

                <button
                    type="submit"
                    class="button"
                >
                    この設定を保存
                </button>
            </form>
        </section>

        <!-- 管理ページアクセス制限 -->
        <section class="access-guard-card">
            <h2>管理ページアクセス制限</h2>

            <p>
                許可IPだけが管理画面へ
                アクセスできます。
            </p>

            <form
                method="post"
                action="<?= url(
                    'admin/extensions/access-guard/settings/admin-access'
                ) ?>"
            >
                <input
                    type="hidden"
                    name="_csrf_token"
                    value="<?= e($csrfToken) ?>"
                >

                <label class="access-guard-switch-row">
                    <input
                        type="checkbox"
                        name="enabled"
                        value="1"
                        <?= $checked(
                            $adminAccess['enabled'] ?? false
                        ) ?>
                    >

                    <span>この機能を有効にする</span>
                </label>

                <button
                    type="submit"
                    class="button"
                >
                    この設定を保存
                </button>
            </form>
        </section>

        <!-- ログインページ変更 -->
        <section class="access-guard-card">
            <h2>ログインページ変更</h2>

            <p>
                標準のログインURLを
                別のURLへ変更します。
            </p>

            <form
                method="post"
                action="<?= url(
                    'admin/extensions/access-guard/settings/login-url'
                ) ?>"
            >
                <input
                    type="hidden"
                    name="_csrf_token"
                    value="<?= e($csrfToken) ?>"
                >

                <label class="access-guard-switch-row">
                    <input
                        type="checkbox"
                        name="enabled"
                        value="1"
                        <?= $checked(
                            $loginUrl['enabled'] ?? false
                        ) ?>
                    >

                    <span>この機能を有効にする</span>
                </label>

                <div class="access-guard-field">
                    <label for="access-guard-login-slug">
                        変更後のURL
                    </label>

                    <div class="access-guard-url-field">
                        <span>/</span>

                        <input
                            type="text"
                            id="access-guard-login-slug"
                            name="slug"
                            value="<?= e(
                                (string)(
                                    $loginUrl['slug'] ??
                                    'secure-login'
                                )
                            ) ?>"
                            maxlength="64"
                            required
                        >
                    </div>
                </div>

                <button
                    type="submit"
                    class="button"
                >
                    この設定を保存
                </button>
            </form>
        </section>

        <!-- ログインロック -->
        <section class="access-guard-card">
            <h2>ログインロック</h2>

            <p>
                ログイン失敗が上限に達したIPを
                一定期間ロックします。
            </p>

            <form
                method="post"
                action="<?= url(
                    'admin/extensions/access-guard/settings/login-lock'
                ) ?>"
            >
                <input
                    type="hidden"
                    name="_csrf_token"
                    value="<?= e($csrfToken) ?>"
                >

                <label class="access-guard-switch-row">
                    <input
                        type="checkbox"
                        name="enabled"
                        value="1"
                        <?= $checked(
                            $loginLock['enabled'] ?? false
                        ) ?>
                    >

                    <span>この機能を有効にする</span>
                </label>

                <div class="access-guard-fields">
                    <div class="access-guard-field">
                        <label for="access-guard-attempts">
                            失敗回数
                        </label>

                        <select
                            id="access-guard-attempts"
                            name="attempts"
                        >
                            <option
                                value="3"
                                <?= $selected(
                                    3,
                                    $loginLock['attempts'] ?? 5
                                ) ?>
                            >
                                3回
                            </option>

                            <option
                                value="5"
                                <?= $selected(
                                    5,
                                    $loginLock['attempts'] ?? 5
                                ) ?>
                            >
                                5回
                            </option>

                            <option
                                value="10"
                                <?= $selected(
                                    10,
                                    $loginLock['attempts'] ?? 5
                                ) ?>
                            >
                                10回
                            </option>
                        </select>
                    </div>

                    <div class="access-guard-field">
                        <label for="access-guard-duration">
                            ロック期間
                        </label>

                        <select
                            id="access-guard-duration"
                            name="duration"
                        >
                            <option
                                value="5"
                                <?= $selected(
                                    5,
                                    $loginLock['duration'] ?? 30
                                ) ?>
                            >
                                5分
                            </option>

                            <option
                                value="15"
                                <?= $selected(
                                    15,
                                    $loginLock['duration'] ?? 30
                                ) ?>
                            >
                                15分
                            </option>

                            <option
                                value="30"
                                <?= $selected(
                                    30,
                                    $loginLock['duration'] ?? 30
                                ) ?>
                            >
                                30分
                            </option>

                            <option
                                value="60"
                                <?= $selected(
                                    60,
                                    $loginLock['duration'] ?? 30
                                ) ?>
                            >
                                1時間
                            </option>

                            <option
                                value="360"
                                <?= $selected(
                                    360,
                                    $loginLock['duration'] ?? 30
                                ) ?>
                            >
                                6時間
                            </option>

                            <option
                                value="1440"
                                <?= $selected(
                                    1440,
                                    $loginLock['duration'] ?? 30
                                ) ?>
                            >
                                24時間
                            </option>
                        </select>
                    </div>
                </div>

                <button
                    type="submit"
                    class="button"
                >
                    この設定を保存
                </button>
            </form>
        </section>

        <!-- フェールワンス -->
        <section class="access-guard-card">
            <h2>フェールワンス</h2>

            <p>
                未承認IPからの正しいログインを
                指定回数だけ失敗させます。
            </p>

            <form
                method="post"
                action="<?= url(
                    'admin/extensions/access-guard/settings/fail-once'
                ) ?>"
            >
                <input
                    type="hidden"
                    name="_csrf_token"
                    value="<?= e($csrfToken) ?>"
                >

                <label class="access-guard-switch-row">
                    <input
                        type="checkbox"
                        name="enabled"
                        value="1"
                        <?= $checked(
                            $failOnce['enabled'] ?? false
                        ) ?>
                    >

                    <span>この機能を有効にする</span>
                </label>

                <div class="access-guard-field">
                    <label for="access-guard-fail-count">
                        失敗させる回数
                    </label>

                    <select
                        id="access-guard-fail-count"
                        name="count"
                    >
                        <option
                            value="1"
                            <?= $selected(
                                1,
                                $failOnce['count'] ?? 1
                            ) ?>
                        >
                            1回
                        </option>

                        <option
                            value="2"
                            <?= $selected(
                                2,
                                $failOnce['count'] ?? 1
                            ) ?>
                        >
                            2回
                        </option>

                        <option
                            value="3"
                            <?= $selected(
                                3,
                                $failOnce['count'] ?? 1
                            ) ?>
                        >
                            3回
                        </option>
                    </select>
                </div>

                <button
                    type="submit"
                    class="button"
                >
                    この設定を保存
                </button>
            </form>
        </section>
    </div>

    <!-- 許可IP -->
    <section class="access-guard-card access-guard-ip-card">
        <h2>許可IP</h2>

        <p>
            ログインページ・管理ページへの
            アクセスを許可するIPです。
        </p>

        <form
            method="post"
            class="access-guard-ip-add"
            action="<?= url(
                'admin/extensions/access-guard/settings/allowed-ip/add'
            ) ?>"
        >
            <input
                type="hidden"
                name="_csrf_token"
                value="<?= e($csrfToken) ?>"
            >

            <input
                type="text"
                name="ip"
                value="<?= e($currentIp) ?>"
                placeholder="例：192.168.1.10"
                required
            >

            <button
                type="submit"
                class="button"
            >
                追加
            </button>
        </form>

        <div class="access-guard-ip-list">
            <?php if (empty($allowedIps)): ?>
                <p class="access-guard-empty">
                    許可IPは登録されていません。
                </p>
            <?php else: ?>
                <?php foreach ($allowedIps as $ip): ?>
                    <div class="access-guard-ip-row">
                        <code><?= e((string)$ip) ?></code>

                        <form
                            method="post"
                            action="<?= url(
                                'admin/extensions/access-guard/settings/allowed-ip/remove'
                            ) ?>"
                        >
                            <input
                                type="hidden"
                                name="_csrf_token"
                                value="<?= e($csrfToken) ?>"
                            >

                            <input
                                type="hidden"
                                name="ip"
                                value="<?= e((string)$ip) ?>"
                            >

                            <button
                                type="submit"
                                class="access-guard-delete"
                            >
                                削除
                            </button>
                        </form>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </section>

    <!-- 拒否IP -->
    <section class="access-guard-card access-guard-ip-card">
        <h2>拒否IP</h2>

        <p>
            ログインページ・管理ページへの
            アクセスを拒否するIPです。
        </p>

        <form
            method="post"
            class="access-guard-ip-add"
            action="<?= url(
                'admin/extensions/access-guard/settings/denied-ip/add'
            ) ?>"
        >
            <input
                type="hidden"
                name="_csrf_token"
                value="<?= e($csrfToken) ?>"
            >

            <input
                type="text"
                name="ip"
                placeholder="例：192.168.1.20"
                required
            >

            <button
                type="submit"
                class="button"
            >
                追加
            </button>
        </form>

        <div class="access-guard-ip-list">
            <?php if (empty($deniedIps)): ?>
                <p class="access-guard-empty">
                    拒否IPは登録されていません。
                </p>
            <?php else: ?>
                <?php foreach ($deniedIps as $ip): ?>
                    <div class="access-guard-ip-row">
                        <code><?= e((string)$ip) ?></code>

                        <form
                            method="post"
                            action="<?= url(
                                'admin/extensions/access-guard/settings/denied-ip/remove'
                            ) ?>"
                        >
                            <input
                                type="hidden"
                                name="_csrf_token"
                                value="<?= e($csrfToken) ?>"
                            >

                            <input
                                type="hidden"
                                name="ip"
                                value="<?= e((string)$ip) ?>"
                            >

                            <button
                                type="submit"
                                class="access-guard-delete"
                            >
                                削除
                            </button>
                        </form>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </section>
</div>