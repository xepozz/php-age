<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Age;
use Xepozz\PhpAge\Bech32;
use Xepozz\PhpAge\X25519Recipient;

class X25519RecipientTest extends TestCase
{
    public function testConstructorWithValidRecipient(): void
    {
        $recipient = 'age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6';
        $r = new X25519Recipient($recipient);
        $stanzas = $r->wrapFileKey(random_bytes(16));
        $this->assertCount(1, $stanzas);
        $this->assertSame('X25519', $stanzas[0]->args[0]);
    }

    public function testConstructorInvalidPrefixThrows(): void
    {
        $bytes = random_bytes(32);
        $encoded = Bech32::encodeFromBytes('foo', $bytes);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid recipient');
        new X25519Recipient($encoded);
    }

    public function testConstructorUppercaseRecipientThrows(): void
    {
        // Uppercase recipient: prefix matches after strtolower but str_starts_with('age1') fails
        $bytes = random_bytes(32);
        $encoded = strtoupper(Bech32::encodeFromBytes('age', $bytes)); // "AGE1..."

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid recipient');
        new X25519Recipient($encoded);
    }

    public function testConstructorWrongByteLengthThrows(): void
    {
        $bytes = random_bytes(16); // 16 bytes instead of 32
        $encoded = Bech32::encodeFromBytes('age', $bytes);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid recipient');
        new X25519Recipient($encoded);
    }

    public function testEncryptFileKey(): void
    {
        $key = random_bytes(32);
        $fileKey = random_bytes(16);
        $encrypted = X25519Recipient::encryptFileKey($fileKey, $key);
        // 16 bytes fileKey + 16 bytes poly1305 tag = 32 bytes
        $this->assertSame(32, strlen($encrypted));
    }

    public function testDecryptFileKeySuccess(): void
    {
        $key = random_bytes(32);
        $fileKey = random_bytes(16);
        $encrypted = X25519Recipient::encryptFileKey($fileKey, $key);
        $decrypted = X25519Recipient::decryptFileKey($encrypted, $key);
        $this->assertSame($fileKey, $decrypted);
    }

    public function testDecryptFileKeyWrongKeyReturnsNull(): void
    {
        $key1 = random_bytes(32);
        $key2 = random_bytes(32);
        $fileKey = random_bytes(16);
        $encrypted = X25519Recipient::encryptFileKey($fileKey, $key1);
        $result = X25519Recipient::decryptFileKey($encrypted, $key2);
        $this->assertNull($result);
    }

    public function testDecryptFileKeyInvalidBodyLengthThrows(): void
    {
        $key = random_bytes(32);
        // Body must be exactly 32 bytes
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid stanza');
        X25519Recipient::decryptFileKey(random_bytes(31), $key);
    }

    public function testDecryptFileKeyInvalidBodyLengthTooLongThrows(): void
    {
        $key = random_bytes(32);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid stanza');
        X25519Recipient::decryptFileKey(random_bytes(33), $key);
    }

    public function testWrapFileKeyProducesValidStanza(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $r = new X25519Recipient($recipient);
        $fileKey = random_bytes(16);
        $stanzas = $r->wrapFileKey($fileKey);

        $this->assertCount(1, $stanzas);
        $this->assertSame('X25519', $stanzas[0]->args[0]);
        $this->assertCount(2, $stanzas[0]->args);
        $this->assertSame(32, strlen($stanzas[0]->body));
    }
}
