<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Armor;

class ArmorTest extends TestCase
{
    public function testEncodeDecodeRoundTrip(): void
    {
        $data = random_bytes(100);
        $encoded = Armor::encode($data);
        $decoded = Armor::decode($encoded);
        $this->assertSame($data, $decoded);
    }

    public function testEncodeDecodeSmallData(): void
    {
        $encoded = Armor::encode('test');
        $decoded = Armor::decode($encoded);
        $this->assertSame('test', $decoded);
    }

    public function testEncodeDecodeLargeData(): void
    {
        // More than 48 bytes per line (forces multiple lines)
        $data = random_bytes(200);
        $encoded = Armor::encode($data);
        $decoded = Armor::decode($encoded);
        $this->assertSame($data, $decoded);
    }

    public function testEncodedFormatHasCorrectHeaderFooter(): void
    {
        $encoded = Armor::encode('test');
        $this->assertStringStartsWith("-----BEGIN AGE ENCRYPTED FILE-----\n", $encoded);
        $this->assertStringEndsWith("-----END AGE ENCRYPTED FILE-----\n", $encoded);
    }

    public function testDecodeHandlesCRLF(): void
    {
        $encoded = "-----BEGIN AGE ENCRYPTED FILE-----\r\ndGVzdA==\r\n-----END AGE ENCRYPTED FILE-----\r\n";
        $decoded = Armor::decode($encoded);
        $this->assertSame('test', $decoded);
    }

    public function testDecodeTrimsWhitespace(): void
    {
        $encoded = "  \n-----BEGIN AGE ENCRYPTED FILE-----\ndGVzdA==\n-----END AGE ENCRYPTED FILE-----\n  ";
        $decoded = Armor::decode($encoded);
        $this->assertSame('test', $decoded);
    }

    public function testDecodeInvalidHeaderThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid header');
        Armor::decode("-----BEGIN WRONG-----\ndGVzdA==\n-----END AGE ENCRYPTED FILE-----");
    }

    public function testDecodeInvalidFooterThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid footer');
        Armor::decode("-----BEGIN AGE ENCRYPTED FILE-----\ndGVzdA==\n-----END WRONG-----");
    }

    public function testDecodeInvalidLineLengthMiddleThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid line length');
        // Middle line shorter than 64 chars (but not the last line)
        $shortLine = str_repeat('A', 32);
        $fullLine = str_repeat('A', 64);
        Armor::decode("-----BEGIN AGE ENCRYPTED FILE-----\n{$shortLine}\n{$fullLine}\n-----END AGE ENCRYPTED FILE-----");
    }

    public function testDecodeInvalidLastLineLengthThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid line length');
        // Last line with length not divisible by 4
        Armor::decode("-----BEGIN AGE ENCRYPTED FILE-----\nABC\n-----END AGE ENCRYPTED FILE-----");
    }

    public function testDecodeEmptyLastLineThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid line length');
        Armor::decode("-----BEGIN AGE ENCRYPTED FILE-----\n\n-----END AGE ENCRYPTED FILE-----");
    }

    public function testDecodeLastLineTooLongThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid line length');
        // Last line longer than 64 chars
        $longLine = str_repeat('AAAA', 17); // 68 chars
        Armor::decode("-----BEGIN AGE ENCRYPTED FILE-----\n{$longLine}\n-----END AGE ENCRYPTED FILE-----");
    }

    public function testDecodeInvalidBase64CharsThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid base64');
        Armor::decode("-----BEGIN AGE ENCRYPTED FILE-----\n!@#\$\n-----END AGE ENCRYPTED FILE-----");
    }

    public function testDecodeBase64DecodeFailsThrows(): void
    {
        // A line with = in wrong positions passes regex but fails base64_decode(strict=true)
        // A full 64-char line with embedded = will pass regex/length checks
        $badLine = str_repeat('A', 60) . '=A=A';
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid base64');
        Armor::decode("-----BEGIN AGE ENCRYPTED FILE-----\n{$badLine}\nAAAA\n-----END AGE ENCRYPTED FILE-----");
    }
}
