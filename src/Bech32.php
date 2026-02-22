<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

/**
 * Bech32 encoding/decoding per BIP173.
 */
final class Bech32
{
    private const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    private const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    /**
     * @param int[] $values
     */
    private static function polymod(array $values): int
    {
        $chk = 1;
        foreach ($values as $v) {
            $b = $chk >> 25;
            $chk = (($chk & 0x1ffffff) << 5) ^ $v;
            for ($i = 0; $i < 5; $i++) {
                $chk ^= (($b >> $i) & 1) ? self::GENERATOR[$i] : 0;
            }
        }
        return $chk;
    }

    /**
     * @return int[]
     */
    private static function hrpExpand(string $hrp): array
    {
        $ret = [];
        $len = strlen($hrp);
        for ($i = 0; $i < $len; $i++) {
            $ret[] = ord($hrp[$i]) >> 5;
        }
        $ret[] = 0;
        for ($i = 0; $i < $len; $i++) {
            $ret[] = ord($hrp[$i]) & 31;
        }
        return $ret;
    }

    /**
     * @param int[] $data
     */
    private static function verifyChecksum(string $hrp, array $data): bool
    {
        return self::polymod(array_merge(self::hrpExpand($hrp), $data)) === 1;
    }

    /**
     * @param int[] $data
     * @return int[]
     */
    private static function createChecksum(string $hrp, array $data): array
    {
        $values = array_merge(self::hrpExpand($hrp), $data, [0, 0, 0, 0, 0, 0]);
        $polymod = self::polymod($values) ^ 1;
        $ret = [];
        for ($i = 0; $i < 6; $i++) {
            $ret[] = ($polymod >> (5 * (5 - $i))) & 31;
        }
        return $ret;
    }

    /**
     * @param int[] $data
     */
    public static function encode(string $hrp, array $data): string
    {
        $combined = array_merge($data, self::createChecksum($hrp, $data));
        $ret = $hrp . '1';
        foreach ($combined as $d) {
            $ret .= self::CHARSET[$d];
        }
        return $ret;
    }

    /**
     * @return array{hrp: string, data: int[]}
     */
    public static function decode(string $bech): array
    {
        $len = strlen($bech);
        // Find the last '1' separator
        $pos = strrpos($bech, '1');
        if ($pos === false || $pos < 1 || $pos + 7 > $len) {
            throw new \InvalidArgumentException('Invalid bech32 string');
        }

        $hrp = substr($bech, 0, $pos);
        $dataStr = substr($bech, $pos + 1);

        // Decode to lowercase for processing
        $lowerDataStr = strtolower($dataStr);

        $data = [];
        $dataLen = strlen($lowerDataStr);
        for ($i = 0; $i < $dataLen; $i++) {
            $d = strpos(self::CHARSET, $lowerDataStr[$i]);
            if ($d === false) {
                throw new \InvalidArgumentException('Invalid bech32 character');
            }
            $data[] = $d;
        }

        $lowerHrp = strtolower($hrp);
        if (!self::verifyChecksum($lowerHrp, $data)) {
            throw new \InvalidArgumentException('Invalid bech32 checksum');
        }

        // Remove checksum (last 6 values)
        return [
            'hrp' => $hrp,
            'data' => array_slice($data, 0, -6),
        ];
    }

    /**
     * Convert between bit groups.
     *
     * @param int[] $data
     * @return int[]
     */
    public static function convertBits(array $data, int $fromBits, int $toBits, bool $pad = true): array
    {
        $acc = 0;
        $bits = 0;
        $ret = [];
        $maxv = (1 << $toBits) - 1;

        foreach ($data as $value) {
            if ($value < 0 || ($value >> $fromBits)) {
                throw new \InvalidArgumentException('Invalid data value');
            }
            $acc = ($acc << $fromBits) | $value;
            $bits += $fromBits;
            while ($bits >= $toBits) {
                $bits -= $toBits;
                $ret[] = ($acc >> $bits) & $maxv;
            }
        }

        if ($pad) {
            if ($bits > 0) {
                $ret[] = ($acc << ($toBits - $bits)) & $maxv;
            }
        } else {
            if ($bits >= $fromBits) {
                throw new \InvalidArgumentException('Invalid padding');
            }
            if (($acc << ($toBits - $bits)) & $maxv) {
                throw new \InvalidArgumentException('Non-zero padding');
            }
        }

        return $ret;
    }

    /**
     * Encode raw bytes with a human-readable prefix.
     */
    public static function encodeFromBytes(string $hrp, string $bytes): string
    {
        if ($bytes === '') {
            throw new \InvalidArgumentException('Invalid bytes');
        }
        $unpacked = unpack('C*', $bytes);
        assert($unpacked !== false);
        /** @var int[] $data */
        $data = array_values($unpacked);
        $words = self::convertBits($data, 8, 5);
        return self::encode($hrp, $words);
    }

    /**
     * Decode bech32 string to raw bytes.
     *
     * @return array{prefix: string, bytes: string}
     */
    public static function decodeToBytes(string $bech): array
    {
        $decoded = self::decode($bech);
        $bytes = self::convertBits($decoded['data'], 5, 8, false);
        return [
            'prefix' => $decoded['hrp'],
            'bytes' => pack('C*', ...$bytes),
        ];
    }
}
