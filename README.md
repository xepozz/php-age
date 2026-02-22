# php-age

A pure PHP implementation of the [age](https://age-encryption.org/) file encryption format, compatible with the [age specification (v1)](https://github.com/C2SP/C2SP/blob/main/age.md).

Built entirely on PHP's `ext-sodium` (libsodium) — no external binary dependencies.

## Features

- **X25519 recipients** — public-key encryption using Curve25519
- **Scrypt passphrases** — password-based encryption with configurable work factor
- **Multiple recipients** — encrypt a file for several public keys at once
- **ASCII armor** — PEM-style encoding/decoding
- **Key generation** — generate identity/recipient key pairs
- **Cross-compatible** — interoperable with [age](https://github.com/FiloSottile/age) (Go), [rage](https://github.com/str4d/rage) (Rust), [typage](https://github.com/nicolo-ribaudo/typage) (TypeScript), and other spec-compliant implementations

## Requirements

- PHP 8.1+
- `ext-sodium` (bundled with PHP since 7.2)

## Installation

```bash
composer require xepozz/php-age
```

## Usage

### Encrypt with a recipient (public key)

```php
use Xepozz\PhpAge\Encrypter;
use Xepozz\PhpAge\Decrypter;

$e = new Encrypter();
$e->addRecipient('age1tgyuvdlmpejqsdf847hevurz9szk7vf3j7ytfyqecgzvphvu2d8qrtaxl6');
$ciphertext = $e->encrypt('hello, world!');

$d = new Decrypter();
$d->addIdentity('AGE-SECRET-KEY-1RKH0DGHQ0FU6VLXX2VW6Y3W2TKK7KR4J36N9SNDXK75JHCJ3N6JQNZJF5J');
$plaintext = $d->decrypt($ciphertext);
// "hello, world!"
```

### Encrypt with a passphrase

```php
use Xepozz\PhpAge\Encrypter;
use Xepozz\PhpAge\Decrypter;

$e = new Encrypter();
$e->setPassphrase('my-secret-passphrase');
$ciphertext = $e->encrypt('hello, world!');

$d = new Decrypter();
$d->addPassphrase('my-secret-passphrase');
$plaintext = $d->decrypt($ciphertext);
// "hello, world!"
```

### Generate a key pair

```php
use Xepozz\PhpAge\Age;

$identity  = Age::generateIdentity();       // AGE-SECRET-KEY-1...
$recipient = Age::identityToRecipient($identity); // age1...
```

### Multiple recipients

```php
use Xepozz\PhpAge\Encrypter;

$e = new Encrypter();
$e->addRecipient('age1...');
$e->addRecipient('age1...');
$ciphertext = $e->encrypt('secret data');
```

### ASCII armor

```php
use Xepozz\PhpAge\Armor;

$encoded = Armor::encode($binaryData);
// -----BEGIN AGE ENCRYPTED FILE-----
// ...base64...
// -----END AGE ENCRYPTED FILE-----

$decoded = Armor::decode($encoded);
```

### Custom scrypt work factor

```php
use Xepozz\PhpAge\Encrypter;

$e = new Encrypter();
$e->setScryptWorkFactor(18); // default is 18 (2^18 = 262144 iterations)
$e->setPassphrase('my-passphrase');
$ciphertext = $e->encrypt('data');
```

## Testing

Run the full test suite:

```bash
vendor/bin/phpunit
```

Run fast tests only (excludes heavy scrypt RFC vectors):

```bash
vendor/bin/phpunit --exclude-group=slow
```

Run with code coverage:

```bash
XDEBUG_MODE=coverage vendor/bin/phpunit --exclude-group=slow --coverage-text
```

## Code coverage

```
Code Coverage Report:

 Summary:
  Classes: 100.00% (13/13)
  Methods: 100.00% (47/47)
  Lines:   100.00% (465/465)

Xepozz\PhpAge\Age .................. Lines: 100.00%
Xepozz\PhpAge\Armor ............... Lines: 100.00%
Xepozz\PhpAge\Bech32 .............. Lines: 100.00%
Xepozz\PhpAge\Decrypter ........... Lines: 100.00%
Xepozz\PhpAge\Encrypter ........... Lines: 100.00%
Xepozz\PhpAge\Header .............. Lines: 100.00%
Xepozz\PhpAge\Scrypt .............. Lines: 100.00%
Xepozz\PhpAge\ScryptIdentity ...... Lines: 100.00%
Xepozz\PhpAge\ScryptRecipient ..... Lines: 100.00%
Xepozz\PhpAge\Stanza .............. Lines: 100.00%
Xepozz\PhpAge\Stream .............. Lines: 100.00%
Xepozz\PhpAge\X25519Identity ...... Lines: 100.00%
Xepozz\PhpAge\X25519Recipient ..... Lines: 100.00%
```

150 tests, 236 assertions — runs in ~0.4 seconds (excluding slow RFC scrypt vectors).

## Specification and references

- [age specification (v1)](https://github.com/C2SP/C2SP/blob/main/age.md) — the format this library implements
- [age (Go)](https://github.com/FiloSottile/age) — the original reference implementation by Filippo Valsorda
- [typage (TypeScript)](https://github.com/nicolo-ribaudo/typage) — TypeScript implementation, used as the reference for this PHP port
- [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914) — scrypt key derivation function
- [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) — X25519 key agreement
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) — ChaCha20-Poly1305 AEAD

## License

MIT
