<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

use WonderNetwork\SshPubkeyPayloadVerification\Github\GithubKeyRepository;
use WonderNetwork\SshPubkeyPayloadVerification\Github\GithubUserSender;
use WonderNetwork\SshPubkeyPayloadVerification\Https\HttpsCertificateRepository;
use WonderNetwork\SshPubkeyPayloadVerification\Https\HttpsSender;
use WonderNetwork\SshPubkeyPayloadVerification\Keyscan\HostSender;
use WonderNetwork\SshPubkeyPayloadVerification\Keyscan\Keyscan;

final class StandardKeyRepository implements KeyRepository {
    public function __construct(
        private GithubKeyRepository $github,
        private HttpsCertificateRepository $ssl,
        private Keyscan $hostKeyscan,
    ) {
    }

    /**
     * @throws KeyException
     */
    public function all(string $sender): KeyCollection {
        $uri = parse_url($sender);
        if (false === $uri || !isset($uri['host'])) {
            throw new UnrecognizedSenderTypeException($sender);
        }

        $host = $uri['host'];
        $keys = match ($uri['scheme'] ?? null) {
            'ssh' => $this->hostKeyscan->all(new HostSender($host, $uri['port'] ?? 22)),
            'github' => $this->github->all(new GithubUserSender($host)),
            'https' => [$this->ssl->all(new HttpsSender($host, $uri['port'] ?? 443))],
            default => throw new UnrecognizedSenderTypeException($sender),
        };

        return KeyCollection::of(...$keys);
    }
}
