<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

final class KeyCollection {
    public static function of(Key ...$keys): self {
        return new self($keys);
    }

    /** @param Key[] $keys */
    private function __construct(private array $keys) {
    }

    public function contains(Key $expected): bool {
        foreach ($this->keys as $key) {
            if ($key->equals($expected)) {
                return true;
            }
        }

        return false;
    }
}
