<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Github;

use Http\Discovery\Psr18Client;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class HttpClientSpy implements ClientInterface {
    public array $calls = [];

    public static function some(): self {
        return new self(client: new Psr18Client());
    }

    private function __construct(private readonly Psr18Client $client) {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface {
        $this->calls[] = (string) $request->getUri();
        return $this->client->createResponse()->withBody(
            $this->client->createStreamFromFile(
                __DIR__ .'/../Resources/gitub-example.keys',
            ),
        );
    }
}
