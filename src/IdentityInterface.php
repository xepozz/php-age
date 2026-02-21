<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

interface IdentityInterface
{
    /**
     * Attempt to unwrap a file key from the given stanzas.
     *
     * @param Stanza[] $stanzas All stanzas from the header
     * @return string|null The 16-byte file key, or null if no stanza matched
     */
    public function unwrapFileKey(array $stanzas): ?string;
}
