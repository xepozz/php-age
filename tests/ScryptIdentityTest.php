<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Header;
use Xepozz\PhpAge\ScryptIdentity;
use Xepozz\PhpAge\ScryptRecipient;
use Xepozz\PhpAge\Stanza;

class ScryptIdentityTest extends TestCase
{
    public function testUnwrapFileKeySuccess(): void
    {
        $passphrase = 'test-passphrase';
        $fileKey = random_bytes(16);

        $recipient = new ScryptRecipient($passphrase, 2);
        $stanzas = $recipient->wrapFileKey($fileKey);

        $identity = new ScryptIdentity($passphrase);
        $unwrapped = $identity->unwrapFileKey($stanzas);
        $this->assertSame($fileKey, $unwrapped);
    }

    public function testUnwrapFileKeySkipsNonScryptStanzas(): void
    {
        $identity = new ScryptIdentity('test');

        // Non-scrypt stanza
        $stanzas = [
            new Stanza(['X25519', Header::base64Encode(random_bytes(32))], str_repeat("\x00", 32)),
        ];

        $result = $identity->unwrapFileKey($stanzas);
        $this->assertNull($result);
    }

    public function testUnwrapFileKeySkipsEmptyArgsStanzas(): void
    {
        $identity = new ScryptIdentity('test');
        $stanzas = [
            new Stanza([], str_repeat("\x00", 32)),
        ];
        $result = $identity->unwrapFileKey($stanzas);
        $this->assertNull($result);
    }

    public function testUnwrapFileKeyMultipleStanzasThrows(): void
    {
        $identity = new ScryptIdentity('test');

        // scrypt stanza cannot be mixed with other stanzas
        $stanzas = [
            new Stanza(['scrypt', Header::base64Encode(random_bytes(16)), '2'], str_repeat("\x00", 32)),
            new Stanza(['X25519', Header::base64Encode(random_bytes(32))], str_repeat("\x00", 32)),
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('scrypt recipient is not the only one in the header');
        $identity->unwrapFileKey($stanzas);
    }

    public function testUnwrapFileKeyWrongArgCountThrows(): void
    {
        $identity = new ScryptIdentity('test');

        // scrypt stanza must have exactly 3 args: ["scrypt", salt, logN]
        $stanzas = [
            new Stanza(['scrypt', Header::base64Encode(random_bytes(16))], str_repeat("\x00", 32)),
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid scrypt stanza');
        $identity->unwrapFileKey($stanzas);
    }

    public function testUnwrapFileKeyInvalidLogNFormatThrows(): void
    {
        $identity = new ScryptIdentity('test');

        // logN must match /^[1-9][0-9]*$/ — "0" starts with 0
        $stanzas = [
            new Stanza(['scrypt', Header::base64Encode(random_bytes(16)), '0'], str_repeat("\x00", 32)),
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid scrypt stanza');
        $identity->unwrapFileKey($stanzas);
    }

    public function testUnwrapFileKeyInvalidLogNLettersThrows(): void
    {
        $identity = new ScryptIdentity('test');

        $stanzas = [
            new Stanza(['scrypt', Header::base64Encode(random_bytes(16)), 'abc'], str_repeat("\x00", 32)),
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid scrypt stanza');
        $identity->unwrapFileKey($stanzas);
    }

    public function testUnwrapFileKeyWrongSaltLengthThrows(): void
    {
        $identity = new ScryptIdentity('test');

        // Salt must be exactly 16 bytes
        $stanzas = [
            new Stanza(['scrypt', Header::base64Encode(random_bytes(10)), '2'], str_repeat("\x00", 32)),
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('invalid scrypt stanza');
        $identity->unwrapFileKey($stanzas);
    }

    public function testUnwrapFileKeyLogNTooHighThrows(): void
    {
        $identity = new ScryptIdentity('test');

        // logN > 20 should fail
        $stanzas = [
            new Stanza(['scrypt', Header::base64Encode(random_bytes(16)), '21'], str_repeat("\x00", 32)),
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('scrypt work factor is too high');
        $identity->unwrapFileKey($stanzas);
    }

    public function testUnwrapFileKeyWrongPassphraseReturnsNull(): void
    {
        $passphrase = 'correct-passphrase';
        $fileKey = random_bytes(16);

        $recipient = new ScryptRecipient($passphrase, 2);
        $stanzas = $recipient->wrapFileKey($fileKey);

        $identity = new ScryptIdentity('wrong-passphrase');
        $result = $identity->unwrapFileKey($stanzas);
        $this->assertNull($result);
    }
}
