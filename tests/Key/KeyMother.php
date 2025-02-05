<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

final class KeyMother {
    public static function some(): Key {
        return new Key(
            type: Key::ECDSA_SHA2_NISTP256,
            publicKey: \implode([
                'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA',
                'BBBHO31cVLUsCYpPNntXam8lZD394gPLQQECiwEU/+g9pQWWKP',
                'PvuFiMBLQsXf84IiNT3nDHbhA0JLZXpQheNEiM0=',
            ]),
        );
    }
}
