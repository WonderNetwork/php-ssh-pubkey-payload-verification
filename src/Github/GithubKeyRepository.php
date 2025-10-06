<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Github;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Throwable;
use WonderNetwork\SshPubkeyPayloadVerification\Key\InvalidKeyTypeException;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyType;

final readonly class GithubKeyRepository {
    public function __construct(
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
    ) {
    }

    /**
     * @param GithubUserSender $sender
     * @return Key[]
     * @throws InvalidKeyTypeException
     * @throws UnableToFetchKeysException
     */
    public function all(GithubUserSender $sender): array {
        $url = \sprintf('https://github.com/%s.keys', $sender->username);
        $request = $this->requestFactory->createRequest('GET', $url);
        try {
            $content = $this->httpClient
                ->sendRequest($request)
                ->getBody()
                ->getContents();
        } catch (ClientExceptionInterface $e) {
            throw new UnableToFetchKeysException(previous: $e);
        }

        return \array_map(
            static function (string $line) {
                [$type, $publicKey] = \array_pad(\explode(" ", \trim($line)), 2, "");
                return Key::fromType(type: $type, publicKey: $publicKey);
            },
            \explode("\n", \trim($content)),
        );
    }
}
