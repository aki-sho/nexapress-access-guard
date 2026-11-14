<?php

/*
 * Access Guardの配布用ZIPを作成
 */

$projectDirectory = __DIR__;

$manifestFile =
    $projectDirectory . '/manifest.json';

/*
 * 必須ファイルを確認
 */
if (!is_file($manifestFile)) {
    exit(
        "manifest.jsonが見つかりません。\n"
    );
}

if (!class_exists(ZipArchive::class)) {
    exit(
        "PHPのZipArchiveが使用できません。\n"
    );
}

if (!is_file($projectDirectory . '/includes/qr-vendor/autoload.php')) {
    fwrite(STDERR, "QRコード生成ライブラリがありません。composer install --no-dev --no-plugins --no-scripts を実行してください。\n");
    exit(1);
}

/*
 * manifest.jsonを読み込む
 */
try {
    $manifest = json_decode(
        file_get_contents($manifestFile),
        true,
        512,
        JSON_THROW_ON_ERROR
    );
} catch (JsonException $exception) {
    exit(
        "manifest.jsonの形式が正しくありません。\n"
    );
}

if (!is_array($manifest)) {
    exit(
        "manifest.jsonを読み込めませんでした。\n"
    );
}

/*
 * 拡張機能IDを確認
 */
$extensionId = trim(
    (string)($manifest['id'] ?? '')
);

if (
    !preg_match(
        '/^[a-zA-Z0-9_-]+$/',
        $extensionId
    )
) {
    exit(
        "拡張機能IDが正しくありません。\n"
    );
}

/*
 * バージョンを確認
 */
$version = trim(
    (string)($manifest['version'] ?? '')
);

if (
    !preg_match(
        '/^\d+\.\d+\.\d+$/',
        $version
    )
) {
    exit(
        "バージョンが正しくありません。\n"
    );
}

/*
 * 更新ZIPのファイル名を取得
 */
$assetPattern = (string)(
    $manifest['update']['asset'] ??
    'nexapress-access-guard-{version}.zip'
);

$outputName = str_replace(
    '{version}',
    $version,
    $assetPattern
);

if (
    basename($outputName) !== $outputName ||
    strtolower(
        pathinfo(
            $outputName,
            PATHINFO_EXTENSION
        )
    ) !== 'zip'
) {
    exit(
        "更新ZIPのファイル名が正しくありません。\n"
    );
}

/*
 * ZIP出力先を準備
 */
$outputDirectory =
    $projectDirectory . '/dist';

$outputFile =
    $outputDirectory . '/' . $outputName;

if (
    !is_dir($outputDirectory) &&
    !mkdir(
        $outputDirectory,
        0755,
        true
    )
) {
    exit(
        "distフォルダを作成できません。\n"
    );
}

if (is_file($outputFile)) {
    unlink($outputFile);
}

/*
 * ZIPを作成
 */
$zip = new ZipArchive();

if (
    $zip->open(
        $outputFile,
        ZipArchive::CREATE |
        ZipArchive::OVERWRITE
    ) !== true
) {
    exit(
        "ZIPファイルを作成できませんでした。\n"
    );
}

/*
 * 配布に必要なファイルとフォルダ
 */
$packagePaths = [
    'admin',
    'assets',
    'bin',
    'includes',
    'bootstrap.php',
    'manifest.json',
    'img.png',
    'README.md',
    'CHANGELOG.md',
    'composer.json',
    'composer.lock',
];

/*
 * 拡張機能のファイルを取得
 */
$iterator = new RecursiveIteratorIterator(
    new RecursiveCallbackFilterIterator(
        new RecursiveDirectoryIterator(
            $projectDirectory,
            FilesystemIterator::SKIP_DOTS
        ),
        static function (SplFileInfo $file) use ($projectDirectory, $packagePaths): bool {
            if ($file->isLink()) {
                return false;
            }
            if ($file->getPath() === $projectDirectory) {
                return in_array($file->getFilename(), $packagePaths, true);
            }

            $relative = str_replace(DIRECTORY_SEPARATOR, '/', substr($file->getPathname(), strlen($projectDirectory) + 1));
            return !str_starts_with($relative, 'includes/qr-vendor/') ||
                !in_array($file->getFilename(), ['test', 'tests', '.github', 'phpunit.xml.dist'], true);
        }
    ),
    RecursiveIteratorIterator::LEAVES_ONLY
);

foreach ($iterator as $file) {
    if (!$file->isFile()) {
        continue;
    }

    $relativePath = substr(
        $file->getPathname(),
        strlen($projectDirectory) + 1
    );

    $relativePath = str_replace(
        DIRECTORY_SEPARATOR,
        '/',
        $relativePath
    );

    /*
     * ZIP内はaccess-guardフォルダから開始
     */
    $zipPath =
        $extensionId
        . '/'
        . $relativePath;

    if (
        !$zip->addFile(
            $file->getPathname(),
            $zipPath
        )
    ) {
        $zip->close();

        if (is_file($outputFile)) {
            unlink($outputFile);
        }

        exit(
            "ZIPへファイルを追加できませんでした："
            . $relativePath
            . "\n"
        );
    }
}

$zip->close();

echo "ZIPファイルを作成しました。\n";
echo $outputFile . "\n";
