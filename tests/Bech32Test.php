<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Bech32;

class Bech32Test extends TestCase
{
    public function testEncodeDecodeRoundTrip(): void
    {
        $bytes = random_bytes(32);
        $encoded = Bech32::encodeFromBytes('age', $bytes);
        $decoded = Bech32::decodeToBytes($encoded);
        $this->assertSame('age', $decoded['prefix']);
        $this->assertSame($bytes, $decoded['bytes']);
    }

    public function testKnownIdentityRecipientPair(): void
    {
        // Decode identity to get scalar
        $identity = 'AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J';
        $decoded = Bech32::decodeToBytes($identity);
        $this->assertSame('AGE-SECRET-KEY-', strtoupper($decoded['prefix']));
        $this->assertSame(32, strlen($decoded['bytes']));

        // Compute recipient
        $publicKey = sodium_crypto_scalarmult_base($decoded['bytes']);
        $recipient = Bech32::encodeFromBytes('age', $publicKey);
        $this->assertSame('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6', $recipient);
    }

    public function testInvalidChecksumThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        // Modify last character to break checksum
        Bech32::decodeToBytes('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl7');
    }
}
