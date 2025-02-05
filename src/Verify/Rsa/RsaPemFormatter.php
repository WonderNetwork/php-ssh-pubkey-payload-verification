<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Rsa;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\BinaryBuffer;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\BitString;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Integer;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Nothing;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\ObjectIdentifier;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Sequence;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\KeyTypeNotAllowedException;

final class RsaPemFormatter {
    /**
     * @throws KeyTypeNotAllowedException
     */
    public function format(Key $key): string {
        if ($key->type() !== Key::RSA) {
            throw new KeyTypeNotAllowedException($key->type());
        }

        $buffer = BinaryBuffer::ofBase64($key->publicKey());
        $alg = $buffer->readString();
        if ($alg !== Key::RSA) {
            throw new KeyTypeNotAllowedException($alg);
        }

        $e = $buffer->readString();
        $n = $buffer->readString();

        /**
         * @link https://www.rfc-editor.org/rfc/rfc8017#appendix-A
         */
        $data = (string) Sequence::of(
            algorithm: Sequence::of(
                algorithm: ObjectIdentifier::rsaEncryption(),
                parameters: new Nothing(),
            ),
            publicKey: BitString::ofPositive(
                (string) Sequence::of(
                    modulus: Integer::of($n),
                    publicExponent: Integer::of($e),
                ),
            ),
        );

        return \implode(
            "\n",
            [
                "-----BEGIN PUBLIC KEY-----",
                ...\str_split(\base64_encode($data), length: 64),
                "-----END PUBLIC KEY-----",
            ],
        );
    }
}
