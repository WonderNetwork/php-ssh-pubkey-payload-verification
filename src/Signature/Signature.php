<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class Signature {
    public function __construct(
        private string $type,
        private string $blob,
    ) {
    }

    public function type(): string {
        return $this->type;
    }

    public function blob(): string {
        return $this->blob;
    }
}
