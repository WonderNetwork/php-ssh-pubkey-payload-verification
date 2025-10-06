<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

final readonly class PubkeyParser {
    public static function parse(BinaryBuffer $buffer): Key {
        $type = $buffer->peakString();
        $pubkey = $buffer->restOfBuffer();
        return Key::fromType(type: $type, publicKey: \base64_encode($pubkey));
    }
}
