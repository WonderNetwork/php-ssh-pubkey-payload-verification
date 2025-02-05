<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify;

use RuntimeException;
use WonderNetwork\SshPubkeyPayloadVerification\ValidatorException;

final class VerifyHandlerNotFoundException extends RuntimeException implements ValidatorException {
    public function __construct(public string $type) {
        parent::__construct(
            \sprintf(
                "There is no handler to verify payloads signed with %s key",
                $type,
            ),
        );
    }
}
