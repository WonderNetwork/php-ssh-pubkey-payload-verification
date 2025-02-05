<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Utilities;

use WonderNetwork\SshPubkeyPayloadVerification\RuntimeValidatorException;

final class ThrowOnWarnings {
    /**
     * @template T of mixed
     * @param callable(): (T|false) $callable
     * @return T
     * @throws RuntimeValidatorException
     */
    public static function run(callable $callable, string $onError): mixed {
        set_error_handler(static function (int $code, string $error) {
            throw new RuntimeValidatorException($error, $code);
        });

        try {
            $result = $callable();
            if (false === $result) {
                throw new RuntimeValidatorException($onError);
            }
            return $result;
        } finally {
            restore_error_handler();
        }
    }
}
