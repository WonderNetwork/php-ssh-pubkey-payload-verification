<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Rsa;

use Exception;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyException;

final class SignatureLengthMismatchException extends Exception implements VerifyException {
    public function __construct(public int $expected, public int $actual) {
        parent::__construct(
            \sprintf(
                'Unexpected signature length. Expected: %d, got: %d',
                $expected,
                $actual,
            ),
        );
    }
}
