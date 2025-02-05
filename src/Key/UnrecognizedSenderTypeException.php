<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

use Exception;

final class UnrecognizedSenderTypeException extends Exception implements KeyException {
    public function __construct(public string $sender) {
        parent::__construct(
            \sprintf(
                'Unrecognized sender type: %s',
                $sender,
            ),
        );
    }
}
