<?php

declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

enum KeyType: string {
    case RSA = 'ssh-rsa';
    case ECDSA_SHA2_NISTP256 = 'ecdsa-sha2-nistp256';
    case ED25519 = 'ssh-ed25519';
}
