<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

final class OpenSSHContainer {
    public function __construct(
        private Key $publicKey,
        private string $namespace,
        private string $reserved,
        private HashAlgorithm $hashAlgorithm,
        private Signature $signature,
    ) {
    }

    public function publicKey(): Key {
        return $this->publicKey;
    }

    public function namespace(): string {
        return $this->namespace;
    }

    public function signature(): Signature {
        return $this->signature;
    }

    public function createSigningPayload(string $message): string {
        $hashed = \hash(algo: $this->hashAlgorithm->value(), data: $message, binary: true);
        return MagicPreamble::VALUE
            .\pack('N', \strlen($this->namespace)).$this->namespace
            .\pack('N', \strlen($this->reserved)).$this->reserved
            .\pack('N', \strlen($this->hashAlgorithm->value())).$this->hashAlgorithm->value()
            .\pack('N', \strlen($hashed)).$hashed;
    }
}
