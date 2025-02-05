<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\ObjectIdentifier;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Sequence;

/**
 * @link https://secg.org/sec1-v2.pdf#subsection.C.3
 */
final class EcPublicKeyType {
    public static function of(Curve $curve): Sequence {
        return Sequence::of(
            id: ObjectIdentifier::ecPublicKey(),
            type: SpecifiedECDomain::of($curve),
        );
    }
}
