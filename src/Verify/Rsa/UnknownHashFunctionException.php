<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Rsa;

use RuntimeException;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyException;

final class UnknownHashFunctionException extends RuntimeException implements VerifyException {
    public function __construct(public string $actual) {
        parent::__construct(
            \sprintf(
                'Unsupported signature hash function: %s',
                $actual,
            ),
        );
    }
}
