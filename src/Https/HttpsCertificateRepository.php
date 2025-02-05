<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Https;

use OpenSSLCertificate;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Ecdsa;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Rsa;
use WonderNetwork\SshPubkeyPayloadVerification\RuntimeValidatorException;
use WonderNetwork\SshPubkeyPayloadVerification\Utilities\ThrowOnWarnings;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa\UnsupportedEllipticCurveException;

final class HttpsCertificateRepository {

    /**
     * @throws CertificateException
     * @throws UnsupportedEllipticCurveException
     */
    public function all(HttpsSender $sender): Key {
        try {
            $socket = ThrowOnWarnings::run(
                callable: static fn () => \stream_socket_client(
                    address: $sender->sslConnect(),
                    context: \stream_context_create(["ssl" => ["capture_peer_cert" => true]]),
                ),
                onError: "Failed stream_socket_client() to {$sender->sslConnect()}",
            );
        } catch (RuntimeValidatorException $e) {
            throw new CertificateException($e->getMessage());
        }

        $params = \stream_context_get_params($socket);
        if (false === isset($params['options']['ssl']) || false === \is_array($params['options']['ssl'])) {
            throw new RuntimeValidatorException("Failed to extract ssl details from context");
        }

        /** @var OpenSSLCertificate $cert */
        $cert = $params['options']['ssl']['peer_certificate']
            ?? throw new RuntimeValidatorException("Failed to extract HTTPS certificate from target host");

        $publicKey = \openssl_pkey_get_public($cert)
            ?: throw new RuntimeValidatorException("Failed to extract public key from HTTPS certificate");

        $keyDetails = \openssl_pkey_get_details($publicKey)
            ?: throw new RuntimeValidatorException("Failed to get public key details");

        return match ($keyDetails["type"]) {
            OPENSSL_KEYTYPE_RSA => Rsa::fromModulusAndExponent(
                $keyDetails['rsa']['n'],
                $keyDetails['rsa']['e'],
            ),
            OPENSSL_KEYTYPE_EC => Ecdsa::fromPoint(
                $keyDetails['ec']['curve_name'],
                $keyDetails['ec']['x'],
                $keyDetails['ec']['y'],
            ),
            default => throw new RuntimeValidatorException("Unsupported key type: $keyDetails[type]"),
        };
    }
}
