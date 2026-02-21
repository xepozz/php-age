<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

final class ScryptRecipient implements RecipientInterface
{
    public function __construct(
        private readonly string $passphrase,
        private readonly int $logN = 18,
    ) {
    }

    public function wrapFileKey(string $fileKey): array
    {
        $salt = random_bytes(16);
        $label = 'age-encryption.org/v1/scrypt';
        $labelAndSalt = $label . $salt;

        $key = Scrypt::derive($this->passphrase, $labelAndSalt, 2 ** $this->logN, 8, 1, 32);
        $body = X25519Recipient::encryptFileKey($fileKey, $key);

        return [new Stanza(['scrypt', Header::base64Encode($salt), (string)$this->logN], $body)];
    }
}
