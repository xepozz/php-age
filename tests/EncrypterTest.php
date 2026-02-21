<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Decrypter;
use Xepozz\PhpAge\Encrypter;
use Xepozz\PhpAge\Age;

class EncrypterTest extends TestCase
{
    public function testEncryptAndDecryptWithPassphrase(): void
    {
        $e = new Encrypter();
        $e->setScryptWorkFactor(12);
        $e->setPassphrase('light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion');
        $encrypted = $e->encrypt('age');

        $d = new Decrypter();
        $d->addPassphrase('light-original-energy-average-wish-blind-vendor-pencil-illness-scorpion');
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame('age', $plaintext);
    }

    public function testEncryptAndDecryptWithRecipient(): void
    {
        $e = new Encrypter();
        $e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
        $encrypted = $e->encrypt('age');

        $d = new Decrypter();
        $d->addIdentity('AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J');
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame('age', $plaintext);
    }

    public function testEncryptAndDecryptWithMultipleRecipients(): void
    {
        $e = new Encrypter();
        $e->addRecipient('age12wv74vxhhp9kg29j2wzm50c9p4urn7py0t4tzdgz6m0pcqjzmu9qqpzjqn');
        $e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
        $encrypted = $e->encrypt('age');

        $d = new Decrypter();
        $d->addIdentity('AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J');
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame('age', $plaintext);
    }

    public function testEncryptAndDecryptWithGeneratedKeys(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $this->assertStringStartsWith('AGE-SECRET-KEY-1', $identity);
        $this->assertStringStartsWith('age1', $recipient);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt('age');

        $d = new Decrypter();
        $d->addIdentity($identity);
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame('age', $plaintext);
    }

    public function testEncryptAndDecryptEmptyPayload(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt('');

        $d = new Decrypter();
        $d->addIdentity($identity);
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame('', $plaintext);
    }

    public function testEncryptAndDecryptLargePayload(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        // Larger than one chunk (64 KiB)
        $data = random_bytes(65536 + 100);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt($data);

        $d = new Decrypter();
        $d->addIdentity($identity);
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame($data, $plaintext);
    }

    public function testEncryptAndDecryptExactChunkSize(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        // Exactly one chunk
        $data = random_bytes(65536);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt($data);

        $d = new Decrypter();
        $d->addIdentity($identity);
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame($data, $plaintext);
    }

    public function testEncryptAndDecryptMultiChunk(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        // Two full chunks + partial
        $data = random_bytes(65536 * 2 + 1);

        $e = new Encrypter();
        $e->addRecipient($recipient);
        $encrypted = $e->encrypt($data);

        $d = new Decrypter();
        $d->addIdentity($identity);
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame($data, $plaintext);
    }

    public function testSetPassphraseTwiceThrows(): void
    {
        $e = new Encrypter();
        $e->setPassphrase('1');
        $this->expectException(\RuntimeException::class);
        $e->setPassphrase('2');
    }

    public function testPassphraseAndRecipientThrows(): void
    {
        $e = new Encrypter();
        $e->setPassphrase('1');
        $this->expectException(\RuntimeException::class);
        $e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
    }

    public function testRecipientAndPassphraseThrows(): void
    {
        $e = new Encrypter();
        $e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
        $this->expectException(\RuntimeException::class);
        $e->setPassphrase('2');
    }

    public function testBadRecipientThrows(): void
    {
        $e = new Encrypter();

        // Truncated
        $this->expectException(\InvalidArgumentException::class);
        $e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl');
    }

    public function testUnrecognizedRecipientTypeThrows(): void
    {
        $e = new Encrypter();
        $this->expectException(\InvalidArgumentException::class);
        $e->addRecipient('foo1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
    }
}
