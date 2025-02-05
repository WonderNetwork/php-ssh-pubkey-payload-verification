<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

use RuntimeException;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\BinaryBuffer;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\Signature;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\UnexpectedTrailingSignatureDataException;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Integer;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Der\Sequence;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\KeyTypeNotAllowedException;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyHandler;

final class EcdsaVerifyHandler implements VerifyHandler {
    private EcdsaPemFormatter $formatter;

    public function __construct() {
        $this->formatter = new EcdsaPemFormatter();
    }

    /**
     * @throws FormatterException
     * @throws KeyTypeNotAllowedException
     * @throws UnexpectedTrailingSignatureDataException
     *
     */
    public function verify(Signature $signature, Key $key, string $payload): bool {
        $opensslPublicKey = \openssl_pkey_get_public(
            $this->formatter->format($key),
        ) ?: throw new RuntimeException('Unable to get openssl public key');

        if ($signature->type() !== $key->type()) {
            throw new KeyTypeNotAllowedException($signature->type());
        }

        /**
         * This technically depends on the number of bits of the curve used in key.
         * But in practice we’re not using _any_ ecdsa key, but specifically
         * `ecdsa-sha2-nistp256`, which means the used key is `prime256v1`,
         * which in turn has 256 bits… As in the name, doh!
         *
         * @see https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L656
         * @see https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L605
         */
        $hashAlgorithm = OPENSSL_ALGO_SHA256;

        $buffer = BinaryBuffer::of($signature->blob());
        $r = $buffer->readString();
        $s = $buffer->readString();
        if (false === $buffer->eof()) {
            throw new UnexpectedTrailingSignatureDataException();
        }

        /**
         * Couldn’t find the actual sources
         *
         * Hint that this function creates a DER sequence:
         * @see https://docs.openssl.org/1.0.2/man3/ecdsa/#description
         * Sample implementation:
         * @see https://github.com/kojo1/wolfssl/blob/fb704774a0e961685e1c082ea13b3e71a4c0d953/src/pk.c#L10466
         */
        $derSignature = (string) Sequence::of(
            Integer::of($r),
            Integer::of($s),
        );

        return 1 === \openssl_verify($payload, $derSignature, $opensslPublicKey, $hashAlgorithm);
    }
}
