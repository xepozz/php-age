<?php

declare(strict_types=1);

namespace Xepozz\PhpAge\Tests;

use PHPUnit\Framework\TestCase;
use Xepozz\PhpAge\Decrypter;
use Xepozz\PhpAge\Encrypter;
use Xepozz\PhpAge\Age;
use Xepozz\PhpAge\RecipientInterface;
use Xepozz\PhpAge\X25519Recipient;

class EncrypterTest extends TestCase
{
    public function testEncryptAndDecryptWithPassphrase(): void
    {
        $e = new Encrypter();
        $e->setScryptWorkFactor(2);
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
        $this->expectExceptionMessage('can encrypt to at most one passphrase');
        $e->setPassphrase('2');
    }

    public function testPassphraseAndRecipientThrows(): void
    {
        $e = new Encrypter();
        $e->setPassphrase('1');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("can't encrypt to both recipients and passphrases");
        $e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
    }

    public function testRecipientAndPassphraseThrows(): void
    {
        $e = new Encrypter();
        $e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("can't encrypt to both recipients and passphrases");
        $e->setPassphrase('2');
    }

    public function testBadRecipientThrows(): void
    {
        $e = new Encrypter();
        $this->expectException(\InvalidArgumentException::class);
        $e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl');
    }

    public function testUnrecognizedRecipientTypeThrows(): void
    {
        $e = new Encrypter();
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('unrecognized recipient type');
        $e->addRecipient('foo1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
    }

    public function testAddRecipientWithInterfaceObject(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $recipientObj = new X25519Recipient($recipient);

        $e = new Encrypter();
        $e->addRecipient($recipientObj);
        $encrypted = $e->encrypt('test-recipient-interface');

        $d = new Decrypter();
        $d->addIdentity($identity);
        $plaintext = $d->decrypt($encrypted);

        $this->assertSame('test-recipient-interface', $plaintext);
    }

    public function testAddCustomRecipientInterface(): void
    {
        $identity = Age::generateIdentity();
        $recipient = Age::identityToRecipient($identity);

        $realRecipient = new X25519Recipient($recipient);
        $customRecipient = new class($realRecipient) implements RecipientInterface {
            public function __construct(private RecipientInterface $inner) {}
            public function wrapFileKey(string $fileKey): array
            {
                return $this->inner->wrapFileKey($fileKey);
            }
        };

        $e = new Encrypter();
        $e->addRecipient($customRecipient);
        $encrypted = $e->encrypt('custom-recipient');

        $d = new Decrypter();
        $d->addIdentity($identity);
        $this->assertSame('custom-recipient', $d->decrypt($encrypted));
    }
}
