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

    public function testEncodedFormatHasCorrectHeaderFooter(): void
    {
        $encoded = Armor::encode('test');
        $this->assertStringStartsWith("-----BEGIN AGE ENCRYPTED FILE-----\n", $encoded);
        $this->assertStringEndsWith("-----END AGE ENCRYPTED FILE-----\n", $encoded);
    }

    public function testDecodeInvalidHeaderThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        Armor::decode("-----BEGIN WRONG-----\ndGVzdA\n-----END AGE ENCRYPTED FILE-----");
    }

    public function testDecodeInvalidFooterThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        Armor::decode("-----BEGIN AGE ENCRYPTED FILE-----\ndGVzdA\n-----END WRONG-----");
    }
}
