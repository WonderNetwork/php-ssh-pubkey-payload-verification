<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class MagicPreamble {
    public const VALUE = 'SSHSIG';

    /**
     * @throws InvalidPreambleException
     */
    public static function validateAndDiscard(string $signature): string {
        $length = \strlen(self::VALUE);
        $preamble = \substr($signature, 0, $length);
        self::validate($preamble);
        return \substr($signature, $length);
    }

    /**
     * @throws InvalidPreambleException
     */
    private static function validate(string $actual): void {
        if ($actual !== self::VALUE) {
            throw new InvalidPreambleException(self::VALUE, $actual);
        }
    }
}
