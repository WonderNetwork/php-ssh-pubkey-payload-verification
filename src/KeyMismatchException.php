<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification;

use Exception;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyCollection;

final class KeyMismatchException extends Exception implements ValidatorException {
    public function __construct(public Key $actual, public KeyCollection $allowed) {
        parent::__construct(strtr(
            <<<EOF
            The message is verified correctly using the provided signature,
            but none of the public keys listed for this sender matches the
            private key used to sign the payload. This might be just a simple
            misconfiguration, but there is nothing proving that the message
            originated from the expected sender and should be discarded.
            EOF,
            ["\n" => " "],
        ));
    }
}
