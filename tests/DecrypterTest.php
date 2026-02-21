<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Age;
use Xepozz\PhpAge\Decrypter;
use Xepozz\PhpAge\Encrypter;
use Xepozz\PhpAge\IdentityInterface;
use Xepozz\PhpAge\X25519Identity;

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
        $d = new Decrypter();
        $d->addIdentity('AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J');

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
        $this->expectExceptionMessage('unrecognized identity type');
        $d->addIdentity('SOMETHING-ELSE-1ABCDEFGH');
    }

    public function testAddIdentityWithInterfaceObject(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt('test-interface');

        $identityObj = new X25519Identity($identity);

        $d = new Decrypter();
        $d->addIdentity($identityObj);
        $plaintext = $d->decrypt($encrypted);
        $this->assertSame('test-interface', $plaintext);
    }

    public function testDecryptInvalidHMACThrows(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt('test');

        // Tamper with the MAC in the header
        $macLinePos = strpos($encrypted, '--- ');
        $macStart = $macLinePos + 4;
        $tampered = $encrypted;
        $tampered[$macStart] = chr(ord($tampered[$macStart]) ^ 0x01);

        $d = new Decrypter();
        $d->addIdentity($identity);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid header HMAC');
        $d->decrypt($tampered);
    }

    public function testDecryptMissingNonceThrows(): void
    {
        // Build a valid encrypted file then truncate payload to < 16 bytes
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt('test');

        $macLinePos = strpos($encrypted, '--- ');
        $headerEnd = strpos($encrypted, "\n", $macLinePos) + 1;
        // Keep only 5 bytes after header — not enough for a 16-byte nonce
        $truncated = substr($encrypted, 0, $headerEnd + 5);

        $d = new Decrypter();
        $d->addIdentity($identity);
        $this->expectException(\RuntimeException::class);
        $d->decrypt($truncated);
    }

    public function testDecryptHeaderInvalidHMACThrows(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt('test');

        $macLinePos = strpos($encrypted, '--- ');
        $headerEnd = strpos($encrypted, "\n", $macLinePos) + 1;
        $header = substr($encrypted, 0, $headerEnd);

        // Tamper with the MAC
        $macStart = $macLinePos + 4;
        $tampered = $header;
        $tampered[$macStart] = chr(ord($tampered[$macStart]) ^ 0x01);

        $d = new Decrypter();
        $d->addIdentity($identity);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid header HMAC');
        $d->decryptHeader($tampered);
    }

    public function testDecryptHeaderNoIdentityMatchThrows(): void
    {
        $identity1 = Age::generateIdentity();
        $recipient1 = Age::identityToRecipient($identity1);
        $identity2 = Age::generateIdentity();

        $e = new Encrypter();
        $e->addRecipient($recipient1);
        $encrypted = $e->encrypt('test');

        $macLinePos = strpos($encrypted, '--- ');
        $headerEnd = strpos($encrypted, "\n", $macLinePos) + 1;
        $header = substr($encrypted, 0, $headerEnd);

        $d = new Decrypter();
        $d->addIdentity($identity2);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("no identity matched any of the file's recipients");
        $d->decryptHeader($header);
    }

    public function testNoIdentityMatchDecryptThrows(): void
    {
        $identity1 = Age::generateIdentity();
        $recipient1 = Age::identityToRecipient($identity1);
        $identity2 = Age::generateIdentity();

        $e = new Encrypter();
        $e->addRecipient($recipient1);
        $encrypted = $e->encrypt('test');

        $d = new Decrypter();
        $d->addIdentity($identity2);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("no identity matched any of the file's recipients");
        $d->decrypt($encrypted);
    }

    public function testAddMultipleIdentitiesFirstNullThenMatch(): void
    {
        // Exercises the loop in unwrapFileKey that tries multiple identities
        $mockIdentity = new class implements IdentityInterface {
            public function unwrapFileKey(array $stanzas): ?string
            {
                return null;
            }
        };

        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt('test');

        $d = new Decrypter();
        $d->addIdentity($mockIdentity);
        $d->addIdentity($identity);

        $plaintext = $d->decrypt($encrypted);
        $this->assertSame('test', $plaintext);
    }
}
