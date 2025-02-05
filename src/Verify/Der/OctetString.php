<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final class OctetString extends TypeLengthValue {
    public static function of(string $value): self {
        return new self($value);
    }

    private function __construct(private string $value) {
    }

    protected function value(): string {
        return $this->value;
    }

    protected function type(): int {
        return 0x04;
    }
}
