<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Age;
use Xepozz\PhpAge\Decrypter;
use Xepozz\PhpAge\Encrypter;

/**
 * Cross-compatibility tests using known test vectors from typage.
 */
class CrossCompatibilityTest extends TestCase
{
    /**
     * Decrypt a file encrypted by typage with scrypt.
     */
    public function testDecryptTypageScryptFile(): void
    {
        $d = new Decrypter();
        $d->addPassphrase('light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion');

        $file = base64_decode(
            'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCB4Y2lkcXJQdmwwZzRROEZ5eXU4dHNnIDgK'
            . 'NnM2Ylp2Vlg2b0NBSVp2QkxCZEhJbEJrYUcreWRIZHVHWVpBaUJkUy9ZMAotLS0gZ280TkNGT05V'
            . 'TDEwZW5WRjVPMnkxem05eWQwdkM0S09hSU1nV05aYW5QSQom4WH7RYXsjlDm3HNKCe9gY2IfCjTY'
            . '/2t6PF4bzUkeWZWkE7kd'
        );
        $this->assertSame("test\n", $d->decrypt($file));
    }

    /**
     * Decrypt a file encrypted by typage with X25519.
     */
    public function testDecryptTypageX25519File(): void
    {
        $d = new Decrypter();
        $d->addIdentity('AGE-SECRET-KEY-1L27NYJDYRNDSCCELNZE8C6JTSH22TLQJVPGD7289KDLMZA5HWN6SZPEHGF');

        $file = base64_decode(
            'YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBOb280UHUyVWZwTllzY3Z5OU1tTjlscHV1'
            . 'Smt4Nng0MEZkdGZoQzd1dVFZCmk0VUNvVmoxbEhHalV0bVR2MHFyRGl0YzNtMXdoY1oyVUtvWDU3'
            . 'MUQwR1EKLS0tIGJ1RTZSYmR6ZlNHSk5tSGl3U2hqR1FFUDF4eEdjSGZtbXlYQUN4SnM4RDAKyqdZ'
            . 'Xpg65sTtmakjxLONtEgaSwXeS8t+7jAWvlleVEFO4/9QIQ'
        );
        $this->assertSame("test\n", $d->decrypt($file));
    }

    /**
     * Verify that identityToRecipient produces the correct recipient.
     */
    public function testIdentityToRecipient(): void
    {
        $recipient = Age::identityToRecipient(
            'AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J'
        );
        $this->assertSame('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6', $recipient);
    }

    /**
     * Test that PHP-encrypted files can be decrypted by PHP.
     */
    public function testEncryptDecryptRoundTrip(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $this->assertStringStartsWith('AGE-SECRET-KEY-1', $identity);
        $this->assertStringStartsWith('age1', $recipient);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt('hello from php-age');

        $d = new Decrypter();
        $d->addIdentity($identity);
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame('hello from php-age', $plaintext);
    }
}
