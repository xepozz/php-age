<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Age;
use Xepozz\PhpAge\Bech32;

class AgeTest extends TestCase
{
    public function testGenerateIdentity(): void
    {
        $identity = Age::generateIdentity();
        $this->assertStringStartsWith('AGE-SECRET-KEY-1', $identity);

        // Verify it decodes to 32 bytes
        $decoded = Bech32::decodeToBytes($identity);
        $this->assertSame(32, strlen($decoded['bytes']));
    }

    public function testIdentityToRecipient(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);
        $this->assertStringStartsWith('age1', $recipient);

        // Verify the recipient decodes to 32 bytes
        $decoded = Bech32::decodeToBytes($recipient);
        $this->assertSame(32, strlen($decoded['bytes']));
    }

    public function testIdentityToRecipientKnownPair(): void
    {
        $recipient = Age::identityToRecipient(
            'AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J'
        );
        $this->assertSame('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6', $recipient);
    }

    public function testIdentityToRecipientWrongPrefixThrows(): void
    {
        // Build a valid bech32 string with wrong prefix
        $bytes = random_bytes(32);
        $encoded = strtoupper(Bech32::encodeFromBytes('wrong-prefix-', $bytes));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid identity');
        Age::identityToRecipient($encoded);
    }

    public function testIdentityToRecipientWrongByteLengthThrows(): void
    {
        $bytes = random_bytes(16); // 16 bytes instead of 32
        $encoded = strtoupper(Bech32::encodeFromBytes('age-secret-key-', $bytes));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid identity');
        Age::identityToRecipient($encoded);
    }

    public function testIdentityToRecipientNotUppercaseStartThrows(): void
    {
        // Build a valid bech32 with right prefix in uppercase, but actual string
        // doesn't start with "AGE-SECRET-KEY-1" (bech32 version)
        // This tests the str_starts_with check on line 35-37
        // Bech32 version is always "1", so this is hard to trigger naturally.
        // We test with a lowercase identity string.
        $bytes = random_bytes(32);
        $encoded = Bech32::encodeFromBytes('age-secret-key-', $bytes);
        // $encoded is lowercase like "age-secret-key-1..."

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid identity');
        Age::identityToRecipient($encoded);
    }

    public function testGenerateIdentityIsUnique(): void
    {
        $id1 = Age::generateIdentity();
        $id2 = Age::generateIdentity();
        $this->assertNotSame($id1, $id2);
    }
}
