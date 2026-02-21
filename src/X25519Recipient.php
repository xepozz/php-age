<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

final class X25519Recipient implements RecipientInterface
{
    private string $recipientPublicKey; // 32 raw bytes

    public function __construct(string $recipient)
    {
        $decoded = Bech32::decodeToBytes($recipient);
        if (strtolower($decoded['prefix']) !== 'age' || strlen($decoded['bytes']) !== 32) {
            throw new \InvalidArgumentException('invalid recipient');
        }
        if (!str_starts_with($recipient, 'age1')) {
            throw new \InvalidArgumentException('invalid recipient');
        }
        $this->recipientPublicKey = $decoded['bytes'];
    }

    public function wrapFileKey(string $fileKey): array
    {
        $ephemeral = random_bytes(32);
        $share = sodium_crypto_scalarmult_base($ephemeral);
        $secret = sodium_crypto_scalarmult($ephemeral, $this->recipientPublicKey);

        $salt = $share . $this->recipientPublicKey;
        $label = 'age-encryption.org/v1/X25519';
        $wrapKey = hash_hkdf('sha256', $secret, 32, $label, $salt);

        $body = self::encryptFileKey($fileKey, $wrapKey);

        return [new Stanza(['X25519', Header::base64Encode($share)], $body)];
    }

    public static function encryptFileKey(string $fileKey, string $key): string
    {
        $nonce = str_repeat("\x00", 12);
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($fileKey, '', $nonce, $key);
    }

    public static function decryptFileKey(string $body, string $key): ?string
    {
        if (strlen($body) !== 32) {
            throw new \RuntimeException('invalid stanza');
        }
        $nonce = str_repeat("\x00", 12);
        $result = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($body, '', $nonce, $key);
        if ($result === false) {
            return null;
        }
        return $result;
    }
}
