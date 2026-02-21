<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Decrypter;
use Xepozz\PhpAge\Header;

class DecrypterTest extends TestCase
{
    public function testDecryptWithPassphrase(): void
    {
        $d = new Decrypter();
        $d->addPassphrase('light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion');

        // From typage tests: scrypt-encrypted "test\n"
        $file = base64_decode(
            'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4Y2lkcXJQdmwwZzRROEZ5eXU4dHNnIDgK'
            . 'NnM2Ylp2Vlg2b0NBSVp2QkxCZEhJbEJrYUcreWRIZHVHWVpBaUJkUy9ZMAotLS0gZ280TkNGT05V'
            . 'TDEwZW5WRjVPMnkxem05eWQwdkM0S09hSU1nV05aYW5QSQom4WH7RYXsjlDm3HNKCe9gY2IfCjTY'
            . '/2t6PF4bzUkeWZWkE7kd'
        );

        $plaintext = $d->decrypt($file);
        $this->assertSame("test\n", $plaintext);
    }

    public function testDecryptWithIdentity(): void
    {
        $d = new Decrypter();
        $d->addIdentity('AGE-SECRET-KEY-1L27NYJDYRNDSCCELNZE8C6JTSH22TLQJVPGD7289KDLMZA5HWN6SZPEHGF');

        // From typage tests: X25519-encrypted "test\n"
        $file = base64_decode(
            'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBOb280UHUyVWZwTllzY3Z5OU1tTjlscHV1'
            . 'Smt4Nng0MEZkdGZoQzd1dVFZCmk0VUNvVmoxbEhHalV0bVR2MHFyRGl0YzNtMXdoY1oyVUtvWDU3'
            . 'MUQwR1EKLS0tIGJ1RTZSYmR6ZlNHSk5tSGl3U2hqR1FFUDF4eEdjSGZtbXlYQUN4SnM4RDAKyqdZ'
            . 'Xpg65sTtmakjxLONtEgaSwXeS8t+7jAWvlleVEFO4/9QIQ'
        );

        $plaintext = $d->decrypt($file);
        $this->assertSame("test\n", $plaintext);
    }

    public function testDecryptDetachedHeader(): void
    {
        $d = new Decrypter();
        $d->addIdentity('AGE-SECRET-KEY-1L27NYJDYRNDSCCELNZE8C6JTSH22TLQJVPGD7289KDLMZA5HWN6SZPEHGF');

        // From typage tests: header-only
        $header = base64_decode(
            'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBOb280UHUyVWZwTllzY3Z5OU1tTjlscHV1'
            . 'Smt4Nng0MEZkdGZoQzd1dVFZCmk0VUNvVmoxbEhHalV0bVR2MHFyRGl0YzNtMXdoY1oyVUtvWDU3'
            . 'MUQwR1EKLS0tIGJ1RTZSYmR6ZlNHSk5tSGl3U2hqR1FFUDF4eEdjSGZtbXlYQUN4SnM4RDAK'
        );

        $fileKey = $d->decryptHeader($header);
        $expected = base64_decode('QEXcQCDq9Zzp2lj+S7omjA');
        $this->assertSame($expected, $fileKey);
    }

    public function testDecryptWithWrongPassphraseFails(): void
    {
        $d = new Decrypter();
        $d->addPassphrase('wrong-passphrase');

        $file = base64_decode(
            'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4Y2lkcXJQdmwwZzRROEZ5eXU4dHNnIDgK'
            . 'NnM2Ylp2Vlg2b0NBSVp2QkxCZEhJbEJrYUcreWRIZHVHWVpBaUJkUy9ZMAotLS0gZ280TkNGT05V'
            . 'TDEwZW5WRjVPMnkxem05eWQwdkM0S09hSU1nV05aYW5QSQom4WH7RYXsjlDm3HNKCe9gY2IfCjTY'
            . '/2t6PF4bzUkeWZWkE7kd'
        );

        $this->expectException(\RuntimeException::class);
        $d->decrypt($file);
    }

    public function testDecryptWithWrongIdentityFails(): void
    {
        // Generate a different identity
        $d = new Decrypter();
        $d->addIdentity('AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J');

        // This file is encrypted for a different recipient
        $file = base64_decode(
            'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBOb280UHUyVWZwTllzY3Z5OU1tTjlscHV1'
            . 'Smt4Nng0MEZkdGZoQzd1dVFZCmk0VUNvVmoxbEhHalV0bVR2MHFyRGl0YzNtMXdoY1oyVUtvWDU3'
            . 'MUQwR1EKLS0tIGJ1RTZSYmR6ZlNHSk5tSGl3U2hqR1FFUDF4eEdjSGZtbXlYQUN4SnM4RDAKyqdZ'
            . 'Xpg65sTtmakjxLONtEgaSwXeS8t+7jAWvlleVEFO4/9QIQ'
        );

        $this->expectException(\RuntimeException::class);
        $d->decrypt($file);
    }

    public function testUnrecognizedIdentityType(): void
    {
        $d = new Decrypter();
        $this->expectException(\InvalidArgumentException::class);
        $d->addIdentity('AGE-SECRET-KEY-FOO-1ABCDEFGH');
    }
}
