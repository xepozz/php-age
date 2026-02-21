<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Header;
use Xepozz\PhpAge\Stanza;

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

    public function testParseInvalidVersionThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid version');
        Header::parse("age-encryption.org/v2\n-> X25519 abc\n--- mac\n");
    }

    public function testParseNoNewlineVersionThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        Header::parse("age-encryption.org/v1");
    }

    public function testParseInvalidHeaderNoMACLine(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid header');
        // Header with version line but stanza start that has no newline after
        Header::parse("age-encryption.org/v1\n");
    }

    public function testParseNonASCIIThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid non-ASCII byte');
        Header::parse("age-encryption.org/v1\n-> X25519 \x01bad\nabc\n--- mac\n");
    }

    public function testParseStanzaWithoutArrowThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid stanza');
        Header::parse("age-encryption.org/v1\nX25519 abc\nabc\n--- mac\n");
    }

    public function testParseStanzaSingleWordThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid stanza');
        // Only "->", no type argument
        Header::parse("age-encryption.org/v1\n->\nabc\n--- mac\n");
    }

    public function testParseStanzaEmptyArgThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid stanza');
        // Double space creates empty arg
        Header::parse("age-encryption.org/v1\n-> X25519  abc\nabc\n--- mac\n");
    }

    public function testParseStanzaBodyNoNewlineThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid stanza');
        // Body line has no trailing newline
        Header::parse("age-encryption.org/v1\n-> X25519 abc\nabc");
    }

    public function testEncodeHeaderNoMACWithExact48ByteBody(): void
    {
        // When body length % 48 == 0, an extra empty line should be added
        $body = str_repeat('A', 48);
        $stanza = new Stanza(['X25519', 'abc'], $body);
        $result = Header::encodeHeaderNoMAC([$stanza]);
        // Should contain an empty body line (just base64 of 48 bytes then empty line)
        $this->assertStringContainsString("\n\n---", $result);
    }

    public function testBase64NoPad(): void
    {
        $this->assertSame('test', Header::base64Decode('dGVzdA'));
        $this->assertSame('test2', Header::base64Decode('dGVzdDI'));
    }

    public function testBase64RejectsNonCanonical(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('non-canonical');
        Header::base64Decode('dGVzdDJ');
    }

    public function testBase64RejectsPadding(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('padding not allowed');
        Header::base64Decode('dGVzdDI=');
    }

    public function testBase64EncodeAndDecode(): void
    {
        $data = random_bytes(50);
        $encoded = Header::base64Encode($data);
        $this->assertFalse(str_contains($encoded, '='));
        $decoded = Header::base64Decode($encoded);
        $this->assertSame($data, $decoded);
    }

    public function testBase64DecodeInvalidCharsThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        Header::base64Decode('!!!invalid');
    }

    public function testParseStanzaBodyLineTooLongThrows(): void
    {
        // A body line that decodes to > 48 bytes
        $longBodyB64 = Header::base64Encode(str_repeat('A', 49));
        $header = "age-encryption.org/v1\n-> X25519 abc\n{$longBodyB64}\n--- mac\n";
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid stanza');
        Header::parse($header);
    }

    public function testParseMultipleStanzas(): void
    {
        $header = "age-encryption.org/v1\n-> X25519 abc\n0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE\n-> scrypt c2FsdA 10\n0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE\n--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM\n";
        $h = Header::parse($header);
        $this->assertCount(2, $h['stanzas']);
        $this->assertSame('X25519', $h['stanzas'][0]->args[0]);
        $this->assertSame('scrypt', $h['stanzas'][1]->args[0]);
    }

    public function testParseHeaderNoPayload(): void
    {
        $header = "age-encryption.org/v1\n-> X25519 abc\n0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE\n--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM\n";
        $h = Header::parse($header);
        $this->assertSame('', $h['rest']);
    }
}
