<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

enum HashAlgorithm: string {
    case SHA256 = 'sha256';
    case SHA512 = 'sha512';
}
