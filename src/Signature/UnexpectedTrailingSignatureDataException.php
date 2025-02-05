<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use Exception;

final class UnexpectedTrailingSignatureDataException extends Exception implements ParserException {
    public function __construct() {
        parent::__construct("The signature contained unexpected trailing data");
    }
}
