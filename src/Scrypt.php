<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

/**
 * Pure PHP implementation of scrypt KDF (RFC 7914).
 *
 * Performance-optimized: Salsa20/8 is fully inlined with no function calls
 * in the hot path to minimize PHP overhead.
 */
final class Scrypt
{
    /**
     * Derive a key using scrypt.
     *
     * @param string $password The password
     * @param string $salt The salt
     * @param int $N CPU/memory cost parameter (must be power of 2)
     * @param int $r Block size parameter
     * @param int $p Parallelization parameter
     * @param int $dkLen Desired key length in bytes
     * @return string The derived key
     */
    public static function derive(string $password, string $salt, int $N, int $r, int $p, int $dkLen): string
    {
        if ($N < 2 || ($N & ($N - 1)) !== 0) {
            throw new \InvalidArgumentException('N must be a power of 2 greater than 1');
        }

        /** @var int<0, max> $pbkdf2Len */
        $pbkdf2Len = $p * 128 * $r;
        $B = hash_pbkdf2('sha256', $password, $salt, 1, $pbkdf2Len, true);

        for ($i = 0; $i < $p; $i++) {
            $block = substr($B, $i * 128 * $r, 128 * $r);
            $block = self::scryptROMix($block, $r, $N);
            $B = substr($B, 0, $i * 128 * $r) . $block . substr($B, ($i + 1) * 128 * $r);
        }

        /** @var int<0, max> $dkLenPositive */
        $dkLenPositive = $dkLen;
        return hash_pbkdf2('sha256', $password, $B, 1, $dkLenPositive, true);
    }

    private static function scryptROMix(string $B, int $r, int $N): string
    {
        $blockSize = 128 * $r;
        $V = [];

        $X = $B;
        for ($i = 0; $i < $N; $i++) {
            $V[$i] = $X;
            $X = self::scryptBlockMix($X, $r);
        }

        for ($i = 0; $i < $N; $i++) {
            /** @var array{1: int} $integerify */
            $integerify = unpack('V', $X, $blockSize - 64);
            $j = $integerify[1] & ($N - 1);
            $X = self::scryptBlockMix($X ^ $V[$j], $r);
        }

        return $X;
    }

    private static function scryptBlockMix(string $B, int $r): string
    {
        $r2 = 2 * $r;

        // Start with X = last 64-byte chunk
        $X = substr($B, ($r2 - 1) * 64, 64);
        $Y = [];

        for ($i = 0; $i < $r2; $i++) {
            // XOR with chunk inline
            $chunk = substr($B, $i * 64, 64);
            $T = $X ^ $chunk;

            // === Inlined Salsa20/8 core ===
            /** @var array<int, int> $unpacked */
            $unpacked = unpack('V16', $T);
            $x0 = $unpacked[1]; $x1 = $unpacked[2]; $x2 = $unpacked[3]; $x3 = $unpacked[4];
            $x4 = $unpacked[5]; $x5 = $unpacked[6]; $x6 = $unpacked[7]; $x7 = $unpacked[8];
            $x8 = $unpacked[9]; $x9 = $unpacked[10]; $x10 = $unpacked[11]; $x11 = $unpacked[12];
            $x12 = $unpacked[13]; $x13 = $unpacked[14]; $x14 = $unpacked[15]; $x15 = $unpacked[16];
            $j0=$x0; $j1=$x1; $j2=$x2; $j3=$x3; $j4=$x4; $j5=$x5; $j6=$x6; $j7=$x7;
            $j8=$x8; $j9=$x9; $j10=$x10; $j11=$x11; $j12=$x12; $j13=$x13; $j14=$x14; $j15=$x15;

            for ($round = 0; $round < 4; $round++) {
                // Column round
                $t = ($x0 + $x12) & 0xffffffff; $x4  ^= (($t << 7) | ($t >> 25)) & 0xffffffff;
                $t = ($x4 + $x0)  & 0xffffffff; $x8  ^= (($t << 9) | ($t >> 23)) & 0xffffffff;
                $t = ($x8 + $x4)  & 0xffffffff; $x12 ^= (($t << 13) | ($t >> 19)) & 0xffffffff;
                $t = ($x12 + $x8) & 0xffffffff; $x0  ^= (($t << 18) | ($t >> 14)) & 0xffffffff;
                $t = ($x5 + $x1)  & 0xffffffff; $x9  ^= (($t << 7) | ($t >> 25)) & 0xffffffff;
                $t = ($x9 + $x5)  & 0xffffffff; $x13 ^= (($t << 9) | ($t >> 23)) & 0xffffffff;
                $t = ($x13 + $x9) & 0xffffffff; $x1  ^= (($t << 13) | ($t >> 19)) & 0xffffffff;
                $t = ($x1 + $x13) & 0xffffffff; $x5  ^= (($t << 18) | ($t >> 14)) & 0xffffffff;
                $t = ($x10 + $x6) & 0xffffffff; $x14 ^= (($t << 7) | ($t >> 25)) & 0xffffffff;
                $t = ($x14 + $x10)& 0xffffffff; $x2  ^= (($t << 9) | ($t >> 23)) & 0xffffffff;
                $t = ($x2 + $x14) & 0xffffffff; $x6  ^= (($t << 13) | ($t >> 19)) & 0xffffffff;
                $t = ($x6 + $x2)  & 0xffffffff; $x10 ^= (($t << 18) | ($t >> 14)) & 0xffffffff;
                $t = ($x15 + $x11)& 0xffffffff; $x3  ^= (($t << 7) | ($t >> 25)) & 0xffffffff;
                $t = ($x3 + $x15) & 0xffffffff; $x7  ^= (($t << 9) | ($t >> 23)) & 0xffffffff;
                $t = ($x7 + $x3)  & 0xffffffff; $x11 ^= (($t << 13) | ($t >> 19)) & 0xffffffff;
                $t = ($x11 + $x7) & 0xffffffff; $x15 ^= (($t << 18) | ($t >> 14)) & 0xffffffff;

                // Row round
                $t = ($x0 + $x3)  & 0xffffffff; $x1  ^= (($t << 7) | ($t >> 25)) & 0xffffffff;
                $t = ($x1 + $x0)  & 0xffffffff; $x2  ^= (($t << 9) | ($t >> 23)) & 0xffffffff;
                $t = ($x2 + $x1)  & 0xffffffff; $x3  ^= (($t << 13) | ($t >> 19)) & 0xffffffff;
                $t = ($x3 + $x2)  & 0xffffffff; $x0  ^= (($t << 18) | ($t >> 14)) & 0xffffffff;
                $t = ($x5 + $x4)  & 0xffffffff; $x6  ^= (($t << 7) | ($t >> 25)) & 0xffffffff;
                $t = ($x6 + $x5)  & 0xffffffff; $x7  ^= (($t << 9) | ($t >> 23)) & 0xffffffff;
                $t = ($x7 + $x6)  & 0xffffffff; $x4  ^= (($t << 13) | ($t >> 19)) & 0xffffffff;
                $t = ($x4 + $x7)  & 0xffffffff; $x5  ^= (($t << 18) | ($t >> 14)) & 0xffffffff;
                $t = ($x10 + $x9) & 0xffffffff; $x11 ^= (($t << 7) | ($t >> 25)) & 0xffffffff;
                $t = ($x11 + $x10)& 0xffffffff; $x8  ^= (($t << 9) | ($t >> 23)) & 0xffffffff;
                $t = ($x8 + $x11) & 0xffffffff; $x9  ^= (($t << 13) | ($t >> 19)) & 0xffffffff;
                $t = ($x9 + $x8)  & 0xffffffff; $x10 ^= (($t << 18) | ($t >> 14)) & 0xffffffff;
                $t = ($x15 + $x14)& 0xffffffff; $x12 ^= (($t << 7) | ($t >> 25)) & 0xffffffff;
                $t = ($x12 + $x15)& 0xffffffff; $x13 ^= (($t << 9) | ($t >> 23)) & 0xffffffff;
                $t = ($x13 + $x12)& 0xffffffff; $x14 ^= (($t << 13) | ($t >> 19)) & 0xffffffff;
                $t = ($x14 + $x13)& 0xffffffff; $x15 ^= (($t << 18) | ($t >> 14)) & 0xffffffff;
            }

            $X = pack('V16',
                ($x0+$j0)&0xffffffff, ($x1+$j1)&0xffffffff, ($x2+$j2)&0xffffffff, ($x3+$j3)&0xffffffff,
                ($x4+$j4)&0xffffffff, ($x5+$j5)&0xffffffff, ($x6+$j6)&0xffffffff, ($x7+$j7)&0xffffffff,
                ($x8+$j8)&0xffffffff, ($x9+$j9)&0xffffffff, ($x10+$j10)&0xffffffff, ($x11+$j11)&0xffffffff,
                ($x12+$j12)&0xffffffff, ($x13+$j13)&0xffffffff, ($x14+$j14)&0xffffffff, ($x15+$j15)&0xffffffff
            );
            // === End inlined Salsa20/8 ===

            $Y[$i] = $X;
        }

        // Reorder: even indices first, then odd
        $result = '';
        for ($i = 0; $i < $r; $i++) {
            $result .= $Y[2 * $i];
        }
        for ($i = 0; $i < $r; $i++) {
            $result .= $Y[2 * $i + 1];
        }

        return $result;
    }
}
