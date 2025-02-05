<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

final class Key {
    public const RSA = 'ssh-rsa';
    public const ECDSA_SHA2_NISTP256 = 'ecdsa-sha2-nistp256';
    public const ED25519 = 'ssh-ed25519';
    public const VALID_KEYS = [
        self::RSA,
        self::ECDSA_SHA2_NISTP256,
        self::ED25519,
    ];

    /**
     * @throws InvalidKeyTypeException
     */
    public function __construct(
        private string $type,
        private string $publicKey,
    ) {
        if (false === \in_array($type, self::VALID_KEYS, true)) {
            throw new InvalidKeyTypeException($type, ...self::VALID_KEYS);
        }
    }

    public function type(): string {
        return $this->type;
    }

    public function publicKey(): string {
        return $this->publicKey;
    }

    public function equals(Key $other): bool {
        return $this->type === $other->type && $this->publicKey === $other->publicKey;
    }
}
