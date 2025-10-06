<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyType;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa\EcdsaVerifyHandler;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Ed25519\Ed25519VerifyHandler;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Rsa\RsaVerifyHandler;

final class VerifyHandlerLocator {
    public function for(Key $key): VerifyHandlerFacade {
        $verifyHandler = match ($key->type) {
            KeyType::RSA => new RsaVerifyHandler(),
            KeyType::ECDSA_SHA2_NISTP256 => new EcdsaVerifyHandler(),
            KeyType::ED25519 => new Ed25519VerifyHandler(),
        };

        return new VerifyHandlerFacade($verifyHandler, $key);
    }
}
