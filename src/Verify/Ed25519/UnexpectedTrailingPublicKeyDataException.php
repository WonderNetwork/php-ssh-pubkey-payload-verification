<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ed25519;

use Exception;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyException;

final class UnexpectedTrailingPublicKeyDataException extends Exception implements VerifyException {
    public function __construct() {
        parent::__construct("Unexpected data found at the end of ed25519 public key");
    }
}
