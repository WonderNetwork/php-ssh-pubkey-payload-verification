<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final class Sequence extends TypeLengthValue {
    public static function of(DataStructure ...$children): self {
        return new self($children);
    }

    /** @param DataStructure[] $children */
    private function __construct(private array $children) {
    }

    protected function value(): string {
        return implode($this->children);
    }

    protected function type(): int {
        return 0x30;
    }
}
