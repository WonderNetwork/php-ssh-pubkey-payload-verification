<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final readonly class BitString extends DataStructure {
    /**
     * @see mpint definition
     * @link https://www.rfc-editor.org/rfc/rfc4251#section-5
     */
    public static function ofPositive(string $value): self {
        // we don’t need to, but ssh-keygen always pads these values
        return self::of("\x00".$value);
    }

    private static function of(string $value): self {
        return new self($value, type: 0x03);
    }
}
