<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\BitString;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Integer;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\ObjectIdentifier;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\OctetString;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Sequence;

/**
 * Syntax for Elliptic Curve Domain Parameters
 * @link https://secg.org/sec1-v2.pdf#subsection.C.2
 */
final class SpecifiedECDomain {
    public static function of(Curve $curve): Sequence {
        return Sequence::of(
            version: Integer::of(Curve::ECDP_VER_1),
            fieldId: Sequence::of(
                id: ObjectIdentifier::primeField(),
                value: Integer::ofPositive($curve->prime()),
            ),
            curve: Sequence::of(
                a: OctetString::of($curve->a()),
                b: OctetString::of($curve->b()),
                seed: BitString::ofPositive($curve->seed()),
            ),
            base: OctetString::of($curve->generator()->uncompressed()),
            order: Integer::ofPositive($curve->order()),
            cofactor: Integer::ofPositive($curve->cofactor()),
        );
    }
}
