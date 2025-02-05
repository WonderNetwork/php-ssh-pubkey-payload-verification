<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\Signature;

interface VerifyHandler {
    /**
     * @throws VerifyException
     */
    public function verify(Signature $signature, Key $key, string $payload): bool;
}
