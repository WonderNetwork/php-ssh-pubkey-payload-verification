<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Rsa;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\Signature;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\KeyTypeNotAllowedException;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyHandler;

final class RsaVerifyHandler implements VerifyHandler {
    private const RSA_MIN_MODULUS_SIZE = 1024;

    private RsaPemFormatter $formatter;

    public function __construct() {
        $this->formatter = new RsaPemFormatter();
    }

    /**
     * @throws InvalidKeyLengthException
     * @throws UnknownHashFunctionException
     * @throws SignatureLengthMismatchException
     * @throws KeyTypeNotAllowedException
     */
    public function verify(Signature $signature, Key $key, string $payload): bool {
        $opensslPublicKey = \openssl_pkey_get_public(
            $this->formatter->format($key),
        ) ?: throw new \RuntimeException('Unable to get openssl public key');

        $details = \openssl_pkey_get_details($opensslPublicKey)
            ?: throw new \RuntimeException('Unable to get openssl public key details');

        $keyLength = $details['bits'];
        if ($keyLength < self::RSA_MIN_MODULUS_SIZE) {
            throw new InvalidKeyLengthException($keyLength, self::RSA_MIN_MODULUS_SIZE);
        }

        $hashAlgorithm = match($signature->type()) {
            'rsa-sha2-256' => OPENSSL_ALGO_SHA256,
            'rsa-sha2-512' => OPENSSL_ALGO_SHA512,
            default => throw new UnknownHashFunctionException($signature->type()),
        };

        $expectedLength = $keyLength / 8;
        $sigblob = $signature->blob();
        $len = \strlen($sigblob);
        if ($len > $expectedLength) {
            throw new SignatureLengthMismatchException($len, $expectedLength);
        }

        if ($len < $expectedLength) {
            // yeah, I read about this in the docs somewhere:
            $sigblob = \str_pad($sigblob, $expectedLength, "\0", STR_PAD_LEFT);
        }

        // max key length check skipped here

        return 1 === \openssl_verify($payload, $sigblob, $opensslPublicKey, $hashAlgorithm);
    }
}
