<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Scrypt;

class ScryptTest extends TestCase
{
    /**
     * Test vector 1 from RFC 7914 Section 12.
     */
    public function testRfc7914Vector1(): void
    {
        $result = Scrypt::derive('', '', 16, 1, 1, 64);
        $expected = hex2bin(
            '77d6576238657b203b19ca42c18a0497'
            . 'f16b4844e3074ae8dfdffa3fede21442'
            . 'fcd0069ded0948f8326a753a0fc81f17'
            . 'e8d3e0fb2e0d3628cf35e20c38d18906'
        );
        $this->assertSame($expected, $result);
    }

    /**
     * Test vector 2 from RFC 7914 Section 12.
     */
    public function testRfc7914Vector2(): void
    {
        $result = Scrypt::derive('password', 'NaCl', 1024, 8, 16, 64);
        $expected = hex2bin(
            'fdbabe1c9d3472007856e7190d01e9fe'
            . '7c6ad7cbc8237830e77376634b373162'
            . '2eaf30d92e22a3886ff109279d9830da'
            . 'c727afb94a83ee6d8360cbdfa2cc0640'
        );
        $this->assertSame($expected, $result);
    }

    /**
     * Test vector 3 from RFC 7914 Section 12.
     */
    public function testRfc7914Vector3(): void
    {
        $result = Scrypt::derive('pleaseletmein', 'SodiumChloride', 16384, 8, 1, 64);
        $expected = hex2bin(
            '7023bdcb3afd7348461c06cd81fd38eb'
            . 'fda8fbba904f8e3ea9b543f6545da1f2'
            . 'd5432955613f0fcf62d49705242a9af9'
            . 'e61e85dc0d651e40dfcf017b45575887'
        );
        $this->assertSame($expected, $result);
    }
}
