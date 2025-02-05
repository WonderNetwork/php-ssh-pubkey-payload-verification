<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

use WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa\UnsupportedEllipticCurveException;

final class Ecdsa {
    public static function fromPoint(string $curve, string $x, string $y): Key {
        return match ($curve) {
            /** @see https://neuromancer.sk/std/x962/prime256v1 */
            'prime256v1' => new Key(
                type: Key::ECDSA_SHA2_NISTP256,
                publicKey: \base64_encode(
                    \pack("N", \strlen('ecdsa-sha2-nistp256')).'ecdsa-sha2-nistp256'
                    .\pack("N", \strlen('nistp256')).'nistp256'
                    // 0x04: compressed form
                    .\pack("N", 1 + \strlen($x) + \strlen($y))."\x04".$x.$y
                ),
            ),
            default => throw new UnsupportedEllipticCurveException($curve),
        };
    }
}
