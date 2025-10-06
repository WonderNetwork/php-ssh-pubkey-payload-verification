<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

final readonly class Key {
    /**
     * @throws InvalidKeyTypeException
     */
    public static function fromType(string $type, string $publicKey): self {
        $keyType = KeyType::tryFrom($type) ?? throw new InvalidKeyTypeException($type);
        return new self($keyType, $publicKey);
    }

    public function __construct(
        public KeyType $type,
        public string $publicKey,
    ) {
    }

    public function equals(Key $other): bool {
        return $this->type === $other->type && $this->publicKey === $other->publicKey;
    }
}
