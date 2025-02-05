<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use Exception;

final class CommandExecutionFailedException extends Exception implements KeyscanException {
    public function __construct(public string $command) {
        parent::__construct(
            \sprintf(
                'Command "%s" failed while getting ssh keys',
                $command,
            ),
        );
    }
}
