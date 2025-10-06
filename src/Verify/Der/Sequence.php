<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final readonly class Sequence extends DataStructure {
    public static function of(DataStructure ...$children): self {
        return new self(\implode("", $children), type: 0x30);
    }
}
