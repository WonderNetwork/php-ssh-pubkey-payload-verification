<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification;

use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyException;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyRepository;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\Parser;
use WonderNetwork\SshPubkeyPayloadVerification\Signature\ParserException;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyException;
use WonderNetwork\SshPubkeyPayloadVerification\Verify\VerifyHandlerLocator;

final class Validator {
    private Parser $parser;
    private VerifyHandlerLocator $verifyHandlerLocator;

    public function __construct(private KeyRepository $publicKeyRepository) {
        $this->parser = new Parser();
        $this->verifyHandlerLocator = new VerifyHandlerLocator();
    }

    /**
     * @throws ParserException Problem parsing the signature
     * @throws KeyException Problem getting allowed public keys for sender
     * @throws NamespaceMismatchException Expected namespace does not match signature
     * @throws KeyMismatchException The key used to sign message does not correspond to any of the sender keys
     * @throws VerifyException There was a problem using the public key to verify the signature
     * @throws VerificationFailedException The message is not correctly signed
     */
    public function validate(string $sender, string $namespace, string $message, string $signature): void {
        $container = $this->parser->parse($signature);
        $allowedKeys = $this->publicKeyRepository->all($sender);

        if ($namespace !== $container->namespace()) {
            throw new NamespaceMismatchException($namespace, $container->namespace());
        }

        $publicKey = $container->publicKey();
        $this->verifyHandlerLocator->for($publicKey)->verify(
            signature: $container->signature(),
            payload: $container->createSigningPayload($message),
        ) ?: throw new VerificationFailedException();

        if (false === $allowedKeys->contains($publicKey)) {
            throw new KeyMismatchException($publicKey, $allowedKeys);
        }
    }
}
