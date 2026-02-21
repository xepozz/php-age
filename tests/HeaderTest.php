<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Header;

class HeaderTest extends TestCase
{
    private const EXAMPLE_HEADER = "age-encryption.org/v1\n-> X25519 abc\n0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE\n--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM\nthis is the payload";

    public function testParseHeader(): void
    {
        $h = Header::parse(self::EXAMPLE_HEADER);

        $this->assertCount(1, $h['stanzas']);
        $this->assertSame(['X25519', 'abc'], $h['stanzas'][0]->args);
        $this->assertSame(
            Header::base64Decode('0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE'),
            $h['stanzas'][0]->body
        );
        $this->assertSame(
            Header::base64Decode('gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM'),
            $h['mac']
        );
        $this->assertSame('this is the payload', $h['rest']);
    }

    public function testReencodeHeader(): void
    {
        $h = Header::parse(self::EXAMPLE_HEADER);
        $this->assertSame(Header::encodeHeaderNoMAC($h['stanzas']), $h['headerNoMAC']);

        $reencoded = Header::encodeHeader($h['stanzas'], $h['mac']) . $h['rest'];
        $this->assertSame(self::EXAMPLE_HEADER, $reencoded);
    }

    public function testBase64NoPad(): void
    {
        $this->assertSame('test', Header::base64Decode('dGVzdA'));
        $this->assertSame('test2', Header::base64Decode('dGVzdDI'));
    }

    public function testBase64RejectsNonCanonical(): void
    {
        $this->expectException(\RuntimeException::class);
        Header::base64Decode('dGVzdDJ');
    }

    public function testBase64RejectsPadding(): void
    {
        $this->expectException(\RuntimeException::class);
        Header::base64Decode('dGVzdDI=');
    }
}
