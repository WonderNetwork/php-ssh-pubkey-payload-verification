<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\BinaryBuffer;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\KeyTypeNotAllowedException;

final class EcdsaPemFormatter {
    private CurveFactory $curveFactory;

    public function __construct() {
        $this->curveFactory = new CurveFactory();
    }

    /**
     * @throws FormatterException
     * @throws UnsupportedEllipticCurveException
     * @throws KeyTypeNotAllowedException
     */
    public function format(Key $key): string {
        if ($key->type() !== Key::ECDSA_SHA2_NISTP256) {
            throw new KeyTypeNotAllowedException($key->type());
        }

        $buffer = BinaryBuffer::ofBase64($key->publicKey());
        $alg = $buffer->readString();
        if ($alg !== Key::ECDSA_SHA2_NISTP256) {
            throw new KeyTypeNotAllowedException($alg);
        }

        $curve = $this->curveFactory->create($buffer->readString());

        $payload = $buffer->readString();

        $data = (string) SubjectPublicKeyInfo::of($curve, $payload);

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
