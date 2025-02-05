<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Github;

use Exception;
use Throwable;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyException;

final class UnableToFetchKeysException extends Exception implements KeyException {
    public function __construct(Throwable $previous) {
        parent::__construct(
            message: "HttpClient error when fetching public keys from github",
            previous: $previous,
        );
    }
}
