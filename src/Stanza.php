<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

final class Stanza
{
    /**
     * @param string[] $args Arguments of the stanza (first is typically the recipient type)
     * @param string $body Raw binary body of the stanza
     */
    public function __construct(
        public readonly array $args,
        public readonly string $body,
    ) {
    }
}
