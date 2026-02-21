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
}
