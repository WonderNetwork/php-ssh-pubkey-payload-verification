<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa\EcdsaVerifyHandler;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Ed25519\Ed25519VerifyHandler;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Rsa\RsaVerifyHandler;

final class VerifyHandlerLocator {
    /**
     * @throws VerifyHandlerNotFoundException
     */
    public function for(Key $key): VerifyHandlerFacade {
        $verifyHandler = match ($key->type()) {
            Key::RSA => new RsaVerifyHandler(),
            Key::ECDSA_SHA2_NISTP256 => new EcdsaVerifyHandler(),
            Key::ED25519 => new Ed25519VerifyHandler(),
            default => throw new VerifyHandlerNotFoundException($key->type()),
        };

        return new VerifyHandlerFacade($verifyHandler, $key);
    }
}
