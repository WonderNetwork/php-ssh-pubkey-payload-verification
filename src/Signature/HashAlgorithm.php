<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class HashAlgorithm {
    private const SHA256 = 'sha256';
    private const SHA512 = 'sha512';

    /**
     * @throws InvalidHashAlgorithmException
     */
    public function __construct(private string $value) {
        if (false === \in_array($value, [self::SHA256, self::SHA512], true)) {
            throw new InvalidHashAlgorithmException($value, self::SHA256, self::SHA512);
        }
    }

    public function value(): string {
        return $this->value;
    }
}
