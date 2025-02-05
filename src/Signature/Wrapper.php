<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class Wrapper {
    private const HEADER = "-----BEGIN SSH SIGNATURE-----";
    private const FOOTER = "-----END SSH SIGNATURE-----";

    /**
     * @throws NotProperlyWrappedException
     */
    public static function unwrap(string $signature): string {
        if (false === \str_starts_with($signature, self::HEADER)) {
            throw new NotProperlyWrappedException();
        }

        if (false === \str_ends_with(\trim($signature), self::FOOTER)) {
            throw new NotProperlyWrappedException();
        }

        return \substr($signature, \strlen(self::HEADER) + 1, - \strlen(self::FOOTER));
    }
}
