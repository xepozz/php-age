<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

final class X25519Identity implements IdentityInterface
{
    private string $secretKey; // 32 raw bytes
    private string $publicKey; // 32 raw bytes

    public function __construct(string $identity)
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
        $this->secretKey = $bytes;
        $this->publicKey = sodium_crypto_scalarmult_base($this->secretKey);
    }

    public function unwrapFileKey(array $stanzas): ?string
    {
        foreach ($stanzas as $s) {
            if (empty($s->args) || $s->args[0] !== 'X25519') {
                continue;
            }
            if (count($s->args) !== 2) {
                throw new \RuntimeException('invalid X25519 stanza');
            }
            $share = Header::base64Decode($s->args[1]);
            if (strlen($share) !== 32) {
                throw new \RuntimeException('invalid X25519 stanza');
            }

            $secret = sodium_crypto_scalarmult($this->secretKey, $share);
            $salt = $share . $this->publicKey;
            $label = 'age-encryption.org/v1/X25519';
            $wrapKey = hash_hkdf('sha256', $secret, 32, $label, $salt);

            $fileKey = X25519Recipient::decryptFileKey($s->body, $wrapKey);
            if ($fileKey !== null) {
                return $fileKey;
            }
        }
        return null;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }
}
