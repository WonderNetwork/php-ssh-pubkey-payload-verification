<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final readonly class Signature {
    public function __construct(
        public string $type,
        public string $blob,
    ) {
    }
}
