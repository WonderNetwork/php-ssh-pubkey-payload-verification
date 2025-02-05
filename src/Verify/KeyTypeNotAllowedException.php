<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify;

use RuntimeException;

final class KeyTypeNotAllowedException extends RuntimeException implements VerifyException {
    public function __construct(public string $actual) {
        parent::__construct(
            \sprintf(
                'Cannot convert "%s" key to PEM format',
                $actual,
            ),
        );
    }
}
