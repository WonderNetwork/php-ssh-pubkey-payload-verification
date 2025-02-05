<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final class Integer extends TypeLengthValue {
    /**
     * @see mpint definition
     * @link https://www.rfc-editor.org/rfc/rfc4251#section-5
     */
    public static function ofPositive(string $value): self {
        $msb = ord($value[0]);
        if ($msb & 0x80) {
            return self::of("\x00".$value);
        }

        return self::of($value);
    }

    public static function of(string $value): self {
        return new self($value);
    }

    private function __construct(private string $value) {
    }

    protected function value(): string {
        return $this->value;
    }

    protected function type(): int {
        return 0x02;
    }
}
