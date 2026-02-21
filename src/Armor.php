<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

/**
 * ASCII armor encoding/decoding (strict PEM subset).
 */
final class Armor
{
    private const HEADER = '-----BEGIN AGE ENCRYPTED FILE-----';
    private const FOOTER = '-----END AGE ENCRYPTED FILE-----';

    public static function encode(string $data): string
    {
        $lines = self::HEADER . "\n";
        $len = strlen($data);
        for ($i = 0; $i < $len; $i += 48) {
            $end = min($i + 48, $len);
            $lines .= base64_encode(substr($data, $i, $end - $i)) . "\n";
        }
        $lines .= self::FOOTER . "\n";
        return $lines;
    }

    public static function decode(string $data): string
    {
        $data = trim(str_replace("\r\n", "\n", $data));
        $lines = explode("\n", $data);

        if (array_shift($lines) !== self::HEADER) {
            throw new \RuntimeException('invalid header');
        }
        if (array_pop($lines) !== self::FOOTER) {
            throw new \RuntimeException('invalid footer');
        }

        $lastIndex = count($lines) - 1;
        foreach ($lines as $i => $line) {
            if ($i === $lastIndex) {
                if (strlen($line) === 0 || strlen($line) > 64 || strlen($line) % 4 !== 0) {
                    throw new \RuntimeException('invalid line length');
                }
            } else {
                if (strlen($line) !== 64) {
                    throw new \RuntimeException('invalid line length');
                }
            }
            if (!preg_match('/^[A-Za-z0-9+\/=]+$/', $line)) {
                throw new \RuntimeException('invalid base64');
            }
        }

        $decoded = base64_decode(implode('', $lines), true);
        if ($decoded === false) {
            throw new \RuntimeException('invalid base64');
        }
        return $decoded;
    }
}
