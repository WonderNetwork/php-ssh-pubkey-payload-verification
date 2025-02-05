<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\BitString;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Sequence;

/**
 * @link https://secg.org/sec1-v2.pdf#subsection.C.3
 */
final class SubjectPublicKeyInfo {
    public static function of(Curve $curve, string $publicKey): Sequence {
        return Sequence::of(
            algorithm: EcPublicKeyType::of($curve),
            subjectPublicKey: BitString::ofPositive($publicKey),
        );
    }
}
