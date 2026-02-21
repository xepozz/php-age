<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

/**
 * age header format encoding/decoding.
 */
final class Header
{
    /**
     * Parse an age header from binary data.
     *
     * @return array{stanzas: Stanza[], mac: string, headerNoMAC: string, headerSize: int, rest: string}
     */
    public static function parse(string $data): array
    {
        $pos = 0;
        $lines = [];

        // Helper to read a line (up to \n)
        $readLine = function () use ($data, &$pos): ?string {
            $nlPos = strpos($data, "\n", $pos);
            if ($nlPos === false) {
                return null;
            }
            $line = substr($data, $pos, $nlPos - $pos);
            $pos = $nlPos + 1;
            // Validate ASCII
            for ($i = 0; $i < strlen($line); $i++) {
                $b = ord($line[$i]);
                if ($b < 32 || $b > 126) {
                    throw new \RuntimeException('invalid non-ASCII byte in header');
                }
            }
            return $line;
        };

        // Parse version line
        $versionLine = $readLine();
        if ($versionLine !== 'age-encryption.org/v1') {
            throw new \RuntimeException('invalid version ' . ($versionLine ?? 'line'));
        }

        $stanzas = [];

        while (true) {
            // Read stanza start or MAC line
            $argsLine = $readLine();
            if ($argsLine === null) {
                throw new \RuntimeException('invalid header');
            }

            // Check if this is the MAC line
            if (str_starts_with($argsLine, '--- ')) {
                $macB64 = substr($argsLine, 4);
                $mac = self::base64Decode($macB64);

                // headerNoMAC = everything up to "---" (not including the MAC value)
                $headerNoMAC = substr($data, 0, $pos - strlen($argsLine) - 1) . '---';
                $headerSize = $pos;
                $rest = substr($data, $pos);

                return [
                    'stanzas' => $stanzas,
                    'mac' => $mac,
                    'headerNoMAC' => $headerNoMAC,
                    'headerSize' => $headerSize,
                    'rest' => $rest,
                ];
            }

            // Parse stanza
            $args = explode(' ', $argsLine);
            if (count($args) < 2 || array_shift($args) !== '->') {
                throw new \RuntimeException('invalid stanza');
            }
            foreach ($args as $arg) {
                if ($arg === '') {
                    throw new \RuntimeException('invalid stanza');
                }
            }

            // Read body lines
            $bodyParts = [];
            while (true) {
                $bodyLine = $readLine();
                if ($bodyLine === null) {
                    throw new \RuntimeException('invalid stanza');
                }
                $decoded = self::base64Decode($bodyLine);
                if (strlen($decoded) > 48) {
                    throw new \RuntimeException('invalid stanza');
                }
                $bodyParts[] = $decoded;
                if (strlen($decoded) < 48) {
                    break;
                }
            }
            $body = implode('', $bodyParts);
            $stanzas[] = new Stanza($args, $body);
        }
    }

    /**
     * Encode header stanzas without the MAC value.
     */
    public static function encodeHeaderNoMAC(array $stanzas): string
    {
        $lines = "age-encryption.org/v1\n";

        foreach ($stanzas as $s) {
            $lines .= '-> ' . implode(' ', $s->args) . "\n";
            $bodyLen = strlen($s->body);
            for ($i = 0; $i < $bodyLen; $i += 48) {
                $end = min($i + 48, $bodyLen);
                $lines .= self::base64Encode(substr($s->body, $i, $end - $i)) . "\n";
            }
            if ($bodyLen % 48 === 0) {
                $lines .= "\n";
            }
        }

        $lines .= '---';
        return $lines;
    }

    /**
     * Encode complete header with MAC.
     */
    public static function encodeHeader(array $stanzas, string $mac): string
    {
        return self::encodeHeaderNoMAC($stanzas) . ' ' . self::base64Encode($mac) . "\n";
    }

    /**
     * Standard base64 without padding (RFC 4648).
     */
    public static function base64Encode(string $data): string
    {
        return rtrim(base64_encode($data), '=');
    }

    /**
     * Standard base64 decode without padding. Rejects padded input and non-canonical encoding.
     */
    public static function base64Decode(string $data): string
    {
        // Reject padding
        if (str_contains($data, '=')) {
            throw new \RuntimeException('invalid base64: padding not allowed');
        }
        // Add padding for PHP's base64_decode
        $padded = $data . str_repeat('=', (4 - strlen($data) % 4) % 4);
        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            throw new \RuntimeException('invalid base64');
        }
        // Verify canonical (re-encode and compare)
        if (rtrim(base64_encode($decoded), '=') !== $data) {
            throw new \RuntimeException('non-canonical base64');
        }
        return $decoded;
    }
}
