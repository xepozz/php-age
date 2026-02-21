<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

/**
 * Key generation and conversion utilities.
 */
final class Age
{
    /**
     * Generate a new X25519 identity.
     *
     * @return string AGE-SECRET-KEY-1... bech32 encoded identity
     */
    public static function generateIdentity(): string
    {
        $scalar = random_bytes(32);
        return strtoupper(Bech32::encodeFromBytes('age-secret-key-', $scalar));
    }

    /**
     * Convert an identity to its corresponding recipient.
     *
     * @param string $identity AGE-SECRET-KEY-1... string
     * @return string age1... recipient string
     */
    public static function identityToRecipient(string $identity): string
    {
        $decoded = Bech32::decodeToBytes($identity);
        $prefix = $decoded['prefix'];
        $bytes = $decoded['bytes'];
        if (strtoupper($prefix) !== 'AGE-SECRET-KEY-' || strlen($bytes) !== 32) {
            throw new \InvalidArgumentException('invalid identity');
        }
        if (!str_starts_with($identity, 'AGE-SECRET-KEY-1')) {
            throw new \InvalidArgumentException('invalid identity');
        }
        $publicKey = sodium_crypto_scalarmult_base($bytes);
        return Bech32::encodeFromBytes('age', $publicKey);
    }
}
