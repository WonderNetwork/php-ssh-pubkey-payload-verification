<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class Base64Decoder {
    /**
     * @throws Base64DecodingException
     */
    public static function decode(string $input): string {
        /** @var string|false $signature */
        $signature = \base64_decode($input);
        if (false === $signature) {
            throw new Base64DecodingException();
        }
        return $signature;
    }
}
