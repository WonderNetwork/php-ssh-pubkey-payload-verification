<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\Signature;

final class VerifyHandlerFacade {
    public function __construct(private VerifyHandler $verifyHandler, private Key $key) {
    }

    /**
     * @throws VerifyException
     */
    public function verify(Signature $signature, string $payload): bool {
        return $this->verifyHandler->verify($signature, $this->key, $payload);
    }
}
