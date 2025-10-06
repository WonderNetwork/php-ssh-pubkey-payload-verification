<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final readonly class OctetString extends DataStructure {
    public static function of(string $value): self {
        return new self($value, type: 0x04);
    }
}
