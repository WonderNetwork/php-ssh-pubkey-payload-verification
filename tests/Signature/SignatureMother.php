<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class SignatureMother {
    public static function some(): Signature {
        return new Signature(
            type: '??',
            blob: '??'
        );
    }
}
