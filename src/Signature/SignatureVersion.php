<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use RuntimeException;

final class SignatureVersion {
    private const VALUE = 1;

    /**
     * @throws InvalidSignatureVersionException
     */
    public static function validateAndDiscard(string $signature): string {
        [1 => $version] = \array_pad(
            \unpack('N', $signature) ?: throw new RuntimeException('Unable to parse signature version'),
            length: 1,
            value: 1,
        );
        self::validate($version);
        return \substr($signature, 4);
    }

    /**
     * @throws InvalidSignatureVersionException
     */
    private static function validate(int $actual): void {
        if ($actual > self::VALUE) {
            throw new InvalidSignatureVersionException(self::VALUE, $actual);
        }
    }
}
