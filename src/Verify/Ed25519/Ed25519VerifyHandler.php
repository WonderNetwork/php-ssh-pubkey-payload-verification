<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ed25519;

use SodiumException;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\BinaryBuffer;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\Signature;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\UnexpectedTrailingSignatureDataException;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\KeyTypeNotAllowedException;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyHandler;

final class Ed25519VerifyHandler implements VerifyHandler {
    /**
     * @throws KeyTypeNotAllowedException
     * @throws UnexpectedTrailingSignatureDataException
     * @throws SodiumException
     */
    public function verify(Signature $signature, Key $key, string $payload): bool {
        $buffer = BinaryBuffer::ofBase64($key->publicKey());
        $type = $buffer->readString();
        if ($key->type() !== $signature->type()) {
            throw new KeyTypeNotAllowedException($signature->type());
        }
        if ($key->type() !== $type) {
            throw new KeyTypeNotAllowedException($type);
        }

        $keyBlob = $buffer->readString();
        if (false === $buffer->eof()) {
            throw new UnexpectedTrailingPublicKeyDataException();
        }

        if (\strlen($signature->blob()) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new UnexpectedTrailingSignatureDataException();
        }

        if (\strlen($keyBlob) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new UnexpectedTrailingSignatureDataException();
        }

        return \sodium_crypto_sign_verify_detached($signature->blob(), $payload, $keyBlob);
    }
}
