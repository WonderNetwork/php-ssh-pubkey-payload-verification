<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use Exception;

final class InvalidHashAlgorithmException extends Exception implements ParserException {
    public function __construct(public string $actual, string ...$expected) {
        parent::__construct(
            \sprintf(
                'Error parsing signature. Hash algorithm: %s, is not one of the expected: %s',
                $actual,
                \implode(', ', $expected),
            ),
        );
    }
}
