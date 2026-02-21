<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

/**
 * STREAM encryption/decryption for age payload.
 *
 * Uses ChaCha20-Poly1305 with 64 KiB chunks.
 * Nonce: 11 bytes big-endian counter + 1 byte last-chunk flag.
 */
final class Stream
{
    private const CHUNK_SIZE = 65536; // 64 KiB
    private const TAG_SIZE = 16; // Poly1305 tag
    private const CHUNK_SIZE_WITH_OVERHEAD = self::CHUNK_SIZE + self::TAG_SIZE;

    /**
     * Encrypt plaintext using STREAM.
     */
    public static function encrypt(string $key, string $plaintext): string
    {
        $result = '';
        $offset = 0;
        $len = strlen($plaintext);
        $counter = 0;

        while (true) {
            $remaining = $len - $offset;
            $isLast = $remaining <= self::CHUNK_SIZE;
            $chunkLen = $isLast ? $remaining : self::CHUNK_SIZE;
            $chunk = substr($plaintext, $offset, $chunkLen);

            $nonce = self::makeNonce($counter, $isLast);
            $encrypted = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($chunk, '', $nonce, $key);
            $result .= $encrypted;

            if ($isLast) {
                break;
            }

            $offset += $chunkLen;
            $counter++;
        }

        return $result;
    }

    /**
     * Decrypt ciphertext using STREAM.
     */
    public static function decrypt(string $key, string $ciphertext): string
    {
        $result = '';
        $offset = 0;
        $len = strlen($ciphertext);
        $counter = 0;
        $firstChunk = true;

        while ($offset < $len) {
            $remaining = $len - $offset;
            $isLast = $remaining <= self::CHUNK_SIZE_WITH_OVERHEAD;
            $chunkLen = $isLast ? $remaining : self::CHUNK_SIZE_WITH_OVERHEAD;
            $chunk = substr($ciphertext, $offset, $chunkLen);

            if (!$isLast) {
                // Non-last chunk: decrypt with last-chunk flag = 0
                $nonce = self::makeNonce($counter, false);
            } else {
                // Last chunk: decrypt with last-chunk flag = 1
                $nonce = self::makeNonce($counter, true);
            }

            $decrypted = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($chunk, '', $nonce, $key);
            if ($decrypted === false) {
                throw new \RuntimeException('STREAM decryption failed');
            }

            if (!$firstChunk && $isLast && strlen($decrypted) === 0) {
                throw new \RuntimeException('final chunk is empty');
            }

            $result .= $decrypted;
            $offset += $chunkLen;
            $counter++;
            $firstChunk = false;
        }

        return $result;
    }

    /**
     * Calculate ciphertext size from plaintext size.
     */
    public static function ciphertextSize(int $plaintextSize): int
    {
        $chunks = max(1, (int)ceil($plaintextSize / self::CHUNK_SIZE));
        return $plaintextSize + self::TAG_SIZE * $chunks;
    }

    /**
     * Calculate plaintext size from ciphertext size.
     */
    public static function plaintextSize(int $ciphertextSize): int
    {
        if ($ciphertextSize < self::TAG_SIZE) {
            throw new \RuntimeException('ciphertext is too small');
        }
        if ($ciphertextSize === self::TAG_SIZE) {
            return 0;
        }
        $fullChunks = intdiv($ciphertextSize, self::CHUNK_SIZE_WITH_OVERHEAD);
        $lastChunk = $ciphertextSize % self::CHUNK_SIZE_WITH_OVERHEAD;
        if ($lastChunk > 0 && $lastChunk <= self::TAG_SIZE) {
            throw new \RuntimeException('ciphertext size is invalid');
        }
        $size = $ciphertextSize;
        $size -= $fullChunks * self::TAG_SIZE;
        $size -= $lastChunk > 0 ? self::TAG_SIZE : 0;
        return $size;
    }

    /**
     * Build a 12-byte nonce from counter and last-chunk flag.
     * First 11 bytes: big-endian counter. Last byte: 0x01 if last, 0x00 otherwise.
     */
    private static function makeNonce(int $counter, bool $isLast): string
    {
        // 11 bytes big-endian counter
        $nonce = str_repeat("\x00", 11);
        $c = $counter;
        for ($i = 10; $i >= 0; $i--) {
            $nonce[$i] = chr($c & 0xff);
            $c >>= 8;
        }
        // Last byte: last-chunk flag
        $nonce .= $isLast ? "\x01" : "\x00";
        return $nonce;
    }
}
