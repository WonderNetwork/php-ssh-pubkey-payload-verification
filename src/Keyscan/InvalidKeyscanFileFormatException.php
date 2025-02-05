<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use Exception;

final class InvalidKeyscanFileFormatException extends Exception implements KeyscanException {
    public function __construct(public string $expected, public string $actual, public int $lineNo) {
        parent::__construct(
            \sprintf(
                'Error parsing keyscan output [line %d]: expected prefix "%s" does not match actual: "%s"',
                $lineNo,
                $expected,
                $actual,
            ),
        );
    }
}
