<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

final readonly class OpenSSHContainer {
    public function __construct(
        public Key $publicKey,
        public string $namespace,
        public string $reserved,
        public HashAlgorithm $hashAlgorithm,
        public Signature $signature,
    ) {
    }

    public function createSigningPayload(string $message): string {
        $hashed = \hash(algo: $this->hashAlgorithm->value, data: $message, binary: true);
        return MagicPreamble::VALUE
            .\pack('N', \strlen($this->namespace)).$this->namespace
            .\pack('N', \strlen($this->reserved)).$this->reserved
            .\pack('N', \strlen($this->hashAlgorithm->value)).$this->hashAlgorithm->value
            .\pack('N', \strlen($hashed)).$hashed;
    }
}
