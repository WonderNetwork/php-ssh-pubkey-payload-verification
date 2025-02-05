<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

use Exception;

final class UnsupportedEllipticCurveException extends Exception implements FormatterException {
    public function __construct(public string $type) {
        parent::__construct(
            \sprintf(
                "Unsupported elliptic curve type '%s'",
                $type,
            ),
        );
    }
}
