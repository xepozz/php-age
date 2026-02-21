<?php

declare(strict_types=1);

namespace Xepozz\PhpAge;

interface RecipientInterface
{
    /**
     * Wrap a file key for this recipient.
     *
     * @param string $fileKey The 16-byte file key to wrap
     * @return Stanza[] One or more stanzas
     */
    public function wrapFileKey(string $fileKey): array;
}
