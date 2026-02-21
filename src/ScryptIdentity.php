<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

final class ScryptIdentity implements IdentityInterface
{
    public function __construct(
        private readonly string $passphrase,
    ) {
    }

    public function unwrapFileKey(array $stanzas): ?string
    {
        foreach ($stanzas as $s) {
            if (empty($s->args) || $s->args[0] !== 'scrypt') {
                continue;
            }
            if (count($stanzas) !== 1) {
                throw new \RuntimeException('scrypt recipient is not the only one in the header');
            }
            if (count($s->args) !== 3) {
                throw new \RuntimeException('invalid scrypt stanza');
            }
            if (!preg_match('/^[1-9][0-9]*$/', $s->args[2])) {
                throw new \RuntimeException('invalid scrypt stanza');
            }
            $salt = Header::base64Decode($s->args[1]);
            if (strlen($salt) !== 16) {
                throw new \RuntimeException('invalid scrypt stanza');
            }

            $logN = (int)$s->args[2];
            if ($logN > 20) {
                throw new \RuntimeException('scrypt work factor is too high');
            }

            $label = 'age-encryption.org/v1/scrypt';
            $labelAndSalt = $label . $salt;
            $key = Scrypt::derive($this->passphrase, $labelAndSalt, 2 ** $logN, 8, 1, 32);

            $fileKey = X25519Recipient::decryptFileKey($s->body, $key);
            if ($fileKey !== null) {
                return $fileKey;
            }
        }
        return null;
    }
}
