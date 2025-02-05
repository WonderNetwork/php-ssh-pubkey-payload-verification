<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

use Exception;

final class InvalidKeyTypeException extends Exception implements KeyException {
    public function __construct(public string $actual, string ...$expected) {
        parent::__construct(
            \sprintf(
                "Provided key type %s is not one of the expected types: %s",
                $actual,
                \implode(', ', $expected),
            ),
        );
    }
}
