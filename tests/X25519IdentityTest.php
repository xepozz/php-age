<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Age;
use Xepozz\PhpAge\Bech32;
use Xepozz\PhpAge\Header;
use Xepozz\PhpAge\Stanza;
use Xepozz\PhpAge\X25519Identity;
use Xepozz\PhpAge\X25519Recipient;

class X25519IdentityTest extends TestCase
{
    public function testConstructorWithValidIdentity(): void
    {
        $identity = Age::generateIdentity();
        $id = new X25519Identity($identity);
        $this->assertSame(32, strlen($id->getPublicKey()));
    }

    public function testGetPublicKey(): void
    {
        $identity = 'AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J';
        $id = new X25519Identity($identity);
        $publicKey = $id->getPublicKey();
        $this->assertSame(32, strlen($publicKey));

        // Verify it matches the expected recipient
        $recipient = Bech32::encodeFromBytes('age', $publicKey);
        $this->assertSame('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6', $recipient);
    }

    public function testConstructorInvalidPrefixThrows(): void
    {
        $bytes = random_bytes(32);
        $encoded = strtoupper(Bech32::encodeFromBytes('wrong-prefix-', $bytes));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid identity');
        new X25519Identity($encoded);
    }

    public function testConstructorLowercaseIdentityThrows(): void
    {
        // Lowercase identity: prefix matches after strtoupper but str_starts_with('AGE-SECRET-KEY-1') fails
        $bytes = random_bytes(32);
        $encoded = Bech32::encodeFromBytes('age-secret-key-', $bytes); // lowercase

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid identity');
        new X25519Identity($encoded);
    }

    public function testConstructorWrongByteLengthThrows(): void
    {
        // Build a valid bech32 string with correct prefix but wrong length
        $bytes = random_bytes(16); // 16 bytes instead of 32
        $encoded = strtoupper(Bech32::encodeFromBytes('age-secret-key-', $bytes));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid identity');
        new X25519Identity($encoded);
    }

    public function testUnwrapFileKeySkipsNonX25519Stanzas(): void
    {
        $identity = Age::generateIdentity();
        $id = new X25519Identity($identity);

        // Create a stanza with a different type
        $stanzas = [
            new Stanza(['scrypt', 'salt', '10'], str_repeat("\x00", 32)),
        ];

        $result = $id->unwrapFileKey($stanzas);
        $this->assertNull($result);
    }

    public function testUnwrapFileKeySkipsEmptyArgsStanzas(): void
    {
        $identity = Age::generateIdentity();
        $id = new X25519Identity($identity);

        // Stanza with empty args
        $stanzas = [
            new Stanza([], str_repeat("\x00", 32)),
        ];

        $result = $id->unwrapFileKey($stanzas);
        $this->assertNull($result);
    }

    public function testUnwrapFileKeyInvalidArgCountThrows(): void
    {
        $identity = Age::generateIdentity();
        $id = new X25519Identity($identity);

        // X25519 stanza with wrong number of args (only 1 arg instead of 2)
        $stanzas = [
            new Stanza(['X25519'], str_repeat("\x00", 32)),
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid X25519 stanza');
        $id->unwrapFileKey($stanzas);
    }

    public function testUnwrapFileKeyInvalidShareLengthThrows(): void
    {
        $identity = Age::generateIdentity();
        $id = new X25519Identity($identity);

        // X25519 stanza with share that decodes to != 32 bytes
        $shortShare = Header::base64Encode(random_bytes(16)); // 16 bytes instead of 32
        $stanzas = [
            new Stanza(['X25519', $shortShare], str_repeat("\x00", 32)),
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid X25519 stanza');
        $id->unwrapFileKey($stanzas);
    }

    public function testUnwrapFileKeyWrongKeyReturnsNull(): void
    {
        // Valid X25519 stanza but for a different recipient — decryptFileKey returns null
        $identity1 = Age::generateIdentity();
        $recipient1 = Age::identityToRecipient($identity1);
        $identity2 = Age::generateIdentity();

        // Wrap file key for identity1's recipient
        $recipientObj = new X25519Recipient($recipient1);
        $stanzas = $recipientObj->wrapFileKey(random_bytes(16));

        // Try to unwrap with identity2
        $id2 = new X25519Identity($identity2);
        $result = $id2->unwrapFileKey($stanzas);
        $this->assertNull($result);
    }

    public function testUnwrapFileKeySuccess(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $fileKey = random_bytes(16);
        $recipientObj = new X25519Recipient($recipient);
        $stanzas = $recipientObj->wrapFileKey($fileKey);

        $id = new X25519Identity($identity);
        $unwrapped = $id->unwrapFileKey($stanzas);
        $this->assertSame($fileKey, $unwrapped);
    }
}
