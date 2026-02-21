<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Stream;

class StreamTest extends TestCase
{
    public static function plaintextSizeProvider(): array
    {
        return [
            [0], [1], [15], [16], [17], [500],
            [64 * 1024 - 1], [64 * 1024], [64 * 1024 + 1],
            [64 * 1024 * 2 - 1], [64 * 1024 * 2], [64 * 1024 * 2 + 1],
        ];
    }

    #[DataProvider('plaintextSizeProvider')]
    public function testRoundTripSizes(int $ps): void
    {
        $cs = Stream::ciphertextSize($ps);
        $this->assertSame($ps, Stream::plaintextSize($cs));
    }

    public static function invalidCiphertextSizeProvider(): array
    {
        return [
            [0], [1], [15],
            [64 * 1024 + 16 + 1], [64 * 1024 + 16 + 15],
            [64 * 1024 * 2 + 16 * 2 + 1], [64 * 1024 * 2 + 16 * 2 + 15],
        ];
    }

    #[DataProvider('invalidCiphertextSizeProvider')]
    public function testInvalidCiphertextSize(int $cs): void
    {
        $this->expectException(\RuntimeException::class);
        Stream::plaintextSize($cs);
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $key = random_bytes(32);
        $plaintext = 'hello, world!';
        $ciphertext = Stream::encrypt($key, $plaintext);
        $decrypted = Stream::decrypt($key, $ciphertext);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testEncryptDecryptEmpty(): void
    {
        $key = random_bytes(32);
        $ciphertext = Stream::encrypt($key, '');
        $decrypted = Stream::decrypt($key, $ciphertext);
        $this->assertSame('', $decrypted);
    }

    public function testEncryptDecryptLargePayload(): void
    {
        $key = random_bytes(32);
        $plaintext = random_bytes(65536 * 2 + 1);
        $ciphertext = Stream::encrypt($key, $plaintext);
        $decrypted = Stream::decrypt($key, $ciphertext);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testDecryptWithWrongKeyFails(): void
    {
        $key1 = random_bytes(32);
        $key2 = random_bytes(32);
        $ciphertext = Stream::encrypt($key1, 'test');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('STREAM decryption failed');
        Stream::decrypt($key2, $ciphertext);
    }

    public function testDecryptCorruptedCiphertext(): void
    {
        $key = random_bytes(32);
        $ciphertext = Stream::encrypt($key, 'test');
        // Flip a bit in the ciphertext
        $ciphertext[5] = chr(ord($ciphertext[5]) ^ 0x01);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('STREAM decryption failed');
        Stream::decrypt($key, $ciphertext);
    }

    public function testPlaintextSizeTooSmallThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ciphertext is too small');
        Stream::plaintextSize(10);
    }

    public function testPlaintextSizeExactTagReturnsZero(): void
    {
        // Exactly 16 bytes (one tag, no data) = empty plaintext
        $this->assertSame(0, Stream::plaintextSize(16));
    }

    public function testCiphertextSizeZero(): void
    {
        // Empty plaintext still has one chunk with a tag
        $this->assertSame(16, Stream::ciphertextSize(0));
    }

    public function testCiphertextSizeExactChunk(): void
    {
        // Exactly one chunk of 65536 bytes
        $this->assertSame(65536 + 16, Stream::ciphertextSize(65536));
    }

    public function testCiphertextSizeMultiChunk(): void
    {
        // Two full chunks
        $this->assertSame(65536 * 2 + 16 * 2, Stream::ciphertextSize(65536 * 2));
    }

    public function testDecryptEmptyFinalChunkThrows(): void
    {
        // Craft a ciphertext where a non-first chunk decrypts to empty
        $key = random_bytes(32);
        $plaintext = random_bytes(65536);

        // Encrypt first chunk (not last): counter=0, isLast=false
        $nonce0 = str_repeat("\x00", 11) . "\x00";
        $chunk0 = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, '', $nonce0, $key);

        // Encrypt empty last chunk: counter=1, isLast=true
        $nonce1 = str_repeat("\x00", 10) . "\x01" . "\x01";
        $chunk1 = sodium_crypto_aead_chacha20poly1305_ietf_encrypt('', '', $nonce1, $key);

        $ciphertext = $chunk0 . $chunk1;

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('final chunk is empty');
        Stream::decrypt($key, $ciphertext);
    }
}
