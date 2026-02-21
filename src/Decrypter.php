<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

final class Decrypter
{
    /** @var IdentityInterface[] */
    private array $identities = [];

    public function addPassphrase(string $passphrase): void
    {
        $this->identities[] = new ScryptIdentity($passphrase);
    }

    /**
     * @param string|IdentityInterface $identity AGE-SECRET-KEY-1... string or IdentityInterface
     */
    public function addIdentity(string|IdentityInterface $identity): void
    {
        if (is_string($identity)) {
            if (str_starts_with($identity, 'AGE-SECRET-KEY-1')) {
                $this->identities[] = new X25519Identity($identity);
            } else {
                throw new \InvalidArgumentException('unrecognized identity type');
            }
        } else {
            $this->identities[] = $identity;
        }
    }

    /**
     * Decrypt a file.
     *
     * @param string $file The encrypted file contents
     * @return string The decrypted plaintext
     */
    public function decrypt(string $file): string
    {
        $parsed = Header::parse($file);
        $fileKey = $this->unwrapFileKey($parsed['stanzas']);
        if ($fileKey === null) {
            throw new \RuntimeException("no identity matched any of the file's recipients");
        }

        // Verify HMAC
        $hmacKey = hash_hkdf('sha256', $fileKey, 32, 'header');
        $mac = hash_hmac('sha256', $parsed['headerNoMAC'], $hmacKey, true);
        if (!hash_equals($mac, $parsed['mac'])) {
            throw new \RuntimeException('invalid header HMAC');
        }

        // Decrypt payload
        $rest = $parsed['rest'];
        if (strlen($rest) < 16) {
            throw new \RuntimeException('missing nonce');
        }
        $nonce = substr($rest, 0, 16);
        $payload = substr($rest, 16);

        $streamKey = hash_hkdf('sha256', $fileKey, 32, 'payload', $nonce);
        return Stream::decrypt($streamKey, $payload);
    }

    /**
     * Decrypt only the header to extract the file key.
     *
     * @param string $header The header data (without payload)
     * @return string The file key
     */
    public function decryptHeader(string $header): string
    {
        $parsed = Header::parse($header);
        $fileKey = $this->unwrapFileKey($parsed['stanzas']);
        if ($fileKey === null) {
            throw new \RuntimeException("no identity matched any of the file's recipients");
        }

        // Verify HMAC
        $hmacKey = hash_hkdf('sha256', $fileKey, 32, 'header');
        $mac = hash_hmac('sha256', $parsed['headerNoMAC'], $hmacKey, true);
        if (!hash_equals($mac, $parsed['mac'])) {
            throw new \RuntimeException('invalid header HMAC');
        }

        return $fileKey;
    }

    /**
     * @param Stanza[] $stanzas
     */
    private function unwrapFileKey(array $stanzas): ?string
    {
        foreach ($this->identities as $identity) {
            $fileKey = $identity->unwrapFileKey($stanzas);
            if ($fileKey !== null) {
                return $fileKey;
            }
        }
        return null;
    }
}
