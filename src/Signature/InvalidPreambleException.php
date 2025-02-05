<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use Exception;

final class InvalidPreambleException extends Exception implements ParserException {
    public function __construct(public string $expected, public string $actual) {
        parent::__construct(
            \sprintf(
                'Error parsing signature. Expected preamble: %s, got: %s',
                $expected,
                $actual,
            ),
        );
    }
}
