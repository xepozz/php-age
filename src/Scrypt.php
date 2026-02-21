<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

/**
 * Pure PHP implementation of scrypt KDF (RFC 7914).
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

        // Step 1: Generate initial data using PBKDF2-HMAC-SHA256
        $B = hash_pbkdf2('sha256', $password, $salt, 1, $p * 128 * $r, true);

        // Step 2: Apply scryptROMix to each block
        for ($i = 0; $i < $p; $i++) {
            $block = substr($B, $i * 128 * $r, 128 * $r);
            $block = self::scryptROMix($block, $r, $N);
            $B = substr($B, 0, $i * 128 * $r) . $block . substr($B, ($i + 1) * 128 * $r);
        }

        // Step 3: Generate output using PBKDF2-HMAC-SHA256
        return hash_pbkdf2('sha256', $password, $B, 1, $dkLen, true);
    }

    /**
     * scryptROMix from RFC 7914.
     */
    private static function scryptROMix(string $B, int $r, int $N): string
    {
        $blockSize = 128 * $r;
        $V = [];

        // Step 1-5
        $X = $B;
        for ($i = 0; $i < $N; $i++) {
            $V[$i] = $X;
            $X = self::scryptBlockMix($X, $r);
        }

        // Step 6-9
        for ($i = 0; $i < $N; $i++) {
            // Integerify: take last 64 bytes of X, interpret first 8 bytes as little-endian
            $lastBlock = substr($X, $blockSize - 64, 64);
            $j = unpack('V', substr($lastBlock, 0, 4))[1] % $N;
            $X = self::scryptBlockMix(($X ^ $V[$j]), $r);
        }

        return $X;
    }

    /**
     * scryptBlockMix from RFC 7914.
     */
    private static function scryptBlockMix(string $B, int $r): string
    {
        // Split B into 2r 64-byte chunks
        $chunks = [];
        for ($i = 0; $i < 2 * $r; $i++) {
            $chunks[$i] = substr($B, $i * 64, 64);
        }

        $X = $chunks[2 * $r - 1];
        $Y = [];

        for ($i = 0; $i < 2 * $r; $i++) {
            $X = self::salsa208($X ^ $chunks[$i]);
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

    /**
     * Salsa20/8 core function.
     */
    private static function salsa208(string $input): string
    {
        $x = array_values(unpack('V16', $input));
        $j = $x;

        for ($round = 0; $round < 4; $round++) {
            // Column round
            $x[ 4] ^= self::rotl32($x[ 0] + $x[12],  7);
            $x[ 8] ^= self::rotl32($x[ 4] + $x[ 0],  9);
            $x[12] ^= self::rotl32($x[ 8] + $x[ 4], 13);
            $x[ 0] ^= self::rotl32($x[12] + $x[ 8], 18);
            $x[ 9] ^= self::rotl32($x[ 5] + $x[ 1],  7);
            $x[13] ^= self::rotl32($x[ 9] + $x[ 5],  9);
            $x[ 1] ^= self::rotl32($x[13] + $x[ 9], 13);
            $x[ 5] ^= self::rotl32($x[ 1] + $x[13], 18);
            $x[14] ^= self::rotl32($x[10] + $x[ 6],  7);
            $x[ 2] ^= self::rotl32($x[14] + $x[10],  9);
            $x[ 6] ^= self::rotl32($x[ 2] + $x[14], 13);
            $x[10] ^= self::rotl32($x[ 6] + $x[ 2], 18);
            $x[ 3] ^= self::rotl32($x[15] + $x[11],  7);
            $x[ 7] ^= self::rotl32($x[ 3] + $x[15],  9);
            $x[11] ^= self::rotl32($x[ 7] + $x[ 3], 13);
            $x[15] ^= self::rotl32($x[11] + $x[ 7], 18);

            // Row round
            $x[ 1] ^= self::rotl32($x[ 0] + $x[ 3],  7);
            $x[ 2] ^= self::rotl32($x[ 1] + $x[ 0],  9);
            $x[ 3] ^= self::rotl32($x[ 2] + $x[ 1], 13);
            $x[ 0] ^= self::rotl32($x[ 3] + $x[ 2], 18);
            $x[ 6] ^= self::rotl32($x[ 5] + $x[ 4],  7);
            $x[ 7] ^= self::rotl32($x[ 6] + $x[ 5],  9);
            $x[ 4] ^= self::rotl32($x[ 7] + $x[ 6], 13);
            $x[ 5] ^= self::rotl32($x[ 4] + $x[ 7], 18);
            $x[11] ^= self::rotl32($x[10] + $x[ 9],  7);
            $x[ 8] ^= self::rotl32($x[11] + $x[10],  9);
            $x[ 9] ^= self::rotl32($x[ 8] + $x[11], 13);
            $x[10] ^= self::rotl32($x[ 9] + $x[ 8], 18);
            $x[12] ^= self::rotl32($x[15] + $x[14],  7);
            $x[13] ^= self::rotl32($x[12] + $x[15],  9);
            $x[14] ^= self::rotl32($x[13] + $x[12], 13);
            $x[15] ^= self::rotl32($x[14] + $x[13], 18);
        }

        $out = '';
        for ($i = 0; $i < 16; $i++) {
            $out .= pack('V', ($x[$i] + $j[$i]) & 0xffffffff);
        }

        return $out;
    }

    private static function rotl32(int $v, int $n): int
    {
        $v &= 0xffffffff;
        return (($v << $n) | ($v >> (32 - $n))) & 0xffffffff;
    }
}
