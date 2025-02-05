<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use Exception;

final class InvalidSignatureVersionException extends Exception implements ParserException {
    public function __construct(public int $expected, public int $actual) {
        parent::__construct(
            \sprintf(
                'Error parsing signature. Expected signature version at most: %d, got: %d',
                $expected,
                $actual,
            ),
        );
    }
}
