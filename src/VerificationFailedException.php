<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification;

use Exception;

final class VerificationFailedException extends Exception implements ValidatorException {
    public function __construct() {
        parent::__construct("Invalid signature");
    }
}
