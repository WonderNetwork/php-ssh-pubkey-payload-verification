<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

final class Rsa {
    public static function fromModulusAndExponent(string $modulus, string $exponent): Key {
        return new Key(
            type: Key::RSA,
            publicKey: \base64_encode(
                \pack("N", \strlen('ssh-rsa')).'ssh-rsa'
                .\pack("N", \strlen($exponent)).$exponent
                .\pack("N", \strlen($modulus)+1)."\x00".$modulus
            ),
        );
    }
}
