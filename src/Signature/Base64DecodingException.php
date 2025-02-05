<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use Exception;

final class Base64DecodingException extends Exception implements ParserException {
    public function __construct() {
        parent::__construct("Failed to decode base64 payload");
    }
}
