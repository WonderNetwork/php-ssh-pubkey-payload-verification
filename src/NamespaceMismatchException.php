<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification;

use Exception;

final class NamespaceMismatchException extends Exception implements ValidatorException {
    public function __construct(public string $expected, public string $actual) {
        parent::__construct(
            \sprintf(
                'Namespace validation failed. Expected: %s, Actual: %s',
                $expected,
                $actual,
            ),
        );
    }
}
