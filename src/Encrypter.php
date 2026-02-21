<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

final class Encrypter
{
    private ?string $passphrase = null;
    private int $scryptWorkFactor = 18;
    /** @var RecipientInterface[] */
    private array $recipients = [];

    public function setPassphrase(string $passphrase): void
    {
        if ($this->passphrase !== null) {
            throw new \RuntimeException('can encrypt to at most one passphrase');
        }
        if ($this->recipients !== []) {
            throw new \RuntimeException("can't encrypt to both recipients and passphrases");
        }
        $this->passphrase = $passphrase;
    }

    public function setScryptWorkFactor(int $logN): void
    {
        $this->scryptWorkFactor = $logN;
    }

    /**
     * @param string|RecipientInterface $recipient Bech32 recipient string (age1...) or RecipientInterface
     */
    public function addRecipient(string|RecipientInterface $recipient): void
    {
        if ($this->passphrase !== null) {
            throw new \RuntimeException("can't encrypt to both recipients and passphrases");
        }

        if (is_string($recipient)) {
            if (str_starts_with($recipient, 'age1')) {
                $this->recipients[] = new X25519Recipient($recipient);
            } else {
                throw new \InvalidArgumentException('unrecognized recipient type');
            }
        } else {
            $this->recipients[] = $recipient;
        }
    }

    public function encrypt(string $plaintext): string
    {
        $fileKey = random_bytes(16);

        $stanzas = [];
        $recipients = $this->recipients;
        if ($this->passphrase !== null) {
            $recipients = [new ScryptRecipient($this->passphrase, $this->scryptWorkFactor)];
        }
        foreach ($recipients as $recipient) {
            foreach ($recipient->wrapFileKey($fileKey) as $stanza) {
                $stanzas[] = $stanza;
            }
        }

        // Compute HMAC
        $hmacKey = hash_hkdf('sha256', $fileKey, 32, 'header');
        $headerNoMAC = Header::encodeHeaderNoMAC($stanzas);
        $mac = hash_hmac('sha256', $headerNoMAC, $hmacKey, true);
        $header = Header::encodeHeader($stanzas, $mac);

        // Payload
        $nonce = random_bytes(16);
        $streamKey = hash_hkdf('sha256', $fileKey, 32, 'payload', $nonce);
        $encrypted = Stream::encrypt($streamKey, $plaintext);

        return $header . $nonce . $encrypted;
    }
}
