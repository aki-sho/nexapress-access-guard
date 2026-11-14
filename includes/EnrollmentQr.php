<?php

namespace NexaPressAccessGuard;

use BaconQrCode\Common\ErrorCorrectionLevel;
use BaconQrCode\Encoder\Encoder;
use Throwable;

class EnrollmentQr
{
    public static function render(string $uri): ?string
    {
        $autoload = __DIR__ . '/qr-vendor/autoload.php';
        if (!is_file($autoload) || !function_exists('iconv')) {
            return null;
        }

        try {
            require_once $autoload;
            $matrix = Encoder::encode($uri, ErrorCorrectionLevel::M())->getMatrix();
        } catch (Throwable $exception) {
            error_log('Access Guard: 登録用QRコードを生成できません。');
            return null;
        }

        $width = $matrix->getWidth();
        $size = $width + 8;
        $path = '';

        // 四辺に4モジュールの余白を設ける。SVGには行列の座標だけを書き込む。
        for ($row = 0; $row < $width; $row++) {
            for ($column = 0; $column < $width; $column++) {
                if ($matrix->get($column, $row) === 1) {
                    $path .= 'M' . ($column + 4) . ' ' . ($row + 4) . 'h1v1h-1z';
                }
            }
        }

        return '<svg xmlns="http://www.w3.org/2000/svg"'
            . ' role="img" aria-label="二要素認証の登録用QRコード"'
            . ' width="224" height="224" viewBox="0 0 ' . $size . ' ' . $size . '" shape-rendering="crispEdges">'
            . '<rect width="' . $size . '" height="' . $size . '" fill="#fff"/>'
            . '<path d="' . $path . '" fill="#000"/></svg>';
    }
}
