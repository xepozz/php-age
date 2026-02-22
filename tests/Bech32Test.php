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
        $identity = 'AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J';
        $decoded = Bech32::decodeToBytes($identity);
        $this->assertSame('AGE-SECRET-KEY-', strtoupper($decoded['prefix']));
        $this->assertSame(32, strlen($decoded['bytes']));

        $publicKey = sodium_crypto_scalarmult_base($decoded['bytes']);
        $recipient = Bech32::encodeFromBytes('age', $publicKey);
        $this->assertSame('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6', $recipient);
    }

    public function testInvalidChecksumThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('checksum');
        Bech32::decodeToBytes('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl7');
    }

    public function testDecodeNoSeparatorThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid bech32 string');
        Bech32::decode('noseparatorhere');
    }

    public function testDecodeTooShortThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid bech32 string');
        // Separator at position 0
        Bech32::decode('1abc');
    }

    public function testDecodeTooShortDataThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Bech32::decode('a1abcde');
    }

    public function testDecodeInvalidCharacterThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid bech32 character');
        // 'b' is valid, but '!' is not in charset
        Bech32::decode('age1!nvalid');
    }

    public function testConvertBitsInvalidDataValueThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid data value');
        // Value 256 is too big for 8-bit
        Bech32::convertBits([256], 8, 5);
    }

    public function testConvertBitsNegativeValueThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid data value');
        Bech32::convertBits([-1], 8, 5);
    }

    public function testConvertBitsInvalidPaddingThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid padding');
        // 5 bits from one 8-bit value, leaving 3 bits which is >= fromBits(5)
        // We need a case where leftover bits >= fromBits
        // fromBits=5, toBits=8: after processing, bits=5 which >= fromBits=5
        Bech32::convertBits([1, 1, 1, 1, 1, 1, 1, 1, 1], 5, 8, false);
    }

    public function testConvertBitsNonZeroPaddingThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Non-zero padding');
        // Two 5-bit values: [0, 1] = 00000 00001, convert to 8-bit (no pad)
        // acc = 0b0000000001, bits = 10, output byte: 0b00000000 (bits=2 remaining)
        // bits=2 < fromBits=5, so we check non-zero padding: (1 << (8-2)) & 0xff = 64 != 0
        Bech32::convertBits([0, 1], 5, 8, false);
    }

    public function testConvertBitsWithPadding(): void
    {
        $result = Bech32::convertBits([0xff], 8, 5, true);
        // 0xff = 11111111 -> 5-bit groups: 11111 111xx -> [31, 28] (padded with zeros on right)
        $this->assertSame([31, 28], $result);
    }

    public function testEncodeFromBytesEmptyThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid bytes');
        Bech32::encodeFromBytes('age', '');
    }

    public function testEncodeDecodeSmallPayload(): void
    {
        $bytes = "\x01\x02";
        $encoded = Bech32::encodeFromBytes('test', $bytes);
        $decoded = Bech32::decodeToBytes($encoded);
        $this->assertSame('test', $decoded['prefix']);
        $this->assertSame($bytes, $decoded['bytes']);
    }
}
