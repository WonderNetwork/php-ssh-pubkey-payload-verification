<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use Exception;

final class NotProperlyWrappedException extends Exception implements ParserException {
    public function __construct() {
        parent::__construct(
            'Error parsing signature. Content not properly wrapped in BEGIN/END SSH SIGNATURE',
        );
    }
}
