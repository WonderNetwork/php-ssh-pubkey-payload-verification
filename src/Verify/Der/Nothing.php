<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final class Nothing extends TypeLengthValue {
    protected function value(): string {
        return "";
    }

    protected function type(): int {
        return 0x05;
    }
}
