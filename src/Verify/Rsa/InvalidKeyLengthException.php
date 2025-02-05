<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Rsa;

use Exception;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyException;

final class InvalidKeyLengthException extends Exception implements VerifyException {
    public function __construct(public int $actual, public int $minLength) {
        parent::__construct(
            \sprintf(
                "Expected RSA key length is at least %d bits, %d given",
                $this->minLength,
                $this->actual,
            ),
        );
    }
}
