<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

final class CurveFactory {
    /**
     * @throws UnsupportedEllipticCurveException
     */
    public function create(string $type): Curve {
        return match ($type) {
            'nistp256' => new NistP256(),
            default => throw new UnsupportedEllipticCurveException($type),
        };
    }
}
