<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification;

use Http\Discovery\Psr18Client;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use WonderNetwork\SshPubkeyPayloadVerification\Github\GithubKeyRepository;
use WonderNetwork\SshPubkeyPayloadVerification\Https\HttpsCertificateRepository;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyRepository;
use WonderNetwork\SshPubkeyPayloadVerification\Key\StandardKeyRepository;
use WonderNetwork\SshPubkeyPayloadVerification\Keyscan\CachedKeyscan;
use WonderNetwork\SshPubkeyPayloadVerification\Keyscan\FileKeyscan;
use WonderNetwork\SshPubkeyPayloadVerification\Keyscan\Keyscan;
use WonderNetwork\SshPubkeyPayloadVerification\Keyscan\ShellExecKeyscan;

final class ValidatorBuilder {
    private ?CacheInterface $cache = null;
    private Keyscan $keyscan;
    private ?KeyRepository $keyRepository = null;
    private ClientInterface $httpClient;
    private RequestFactoryInterface $requestFactory;

    public static function start(): self {
        return new self();
    }

    private function __construct() {
        $this->keyscan = new ShellExecKeyscan();
        $this->httpClient = new Psr18Client();
        $this->requestFactory = new Psr18Client();
    }

    public function withCache(CacheInterface $cache): self {
        $this->cache = $cache;
        return $this;
    }

    public function withCustomKeyRepository(KeyRepository $keyRepository): self {
        $this->keyRepository = $keyRepository;
        return $this;
    }

    public function withHttpClient(ClientInterface $httpClient): self {
        $this->httpClient = $httpClient;
        return $this;
    }

    public function withHttpMessageFactory(RequestFactoryInterface $requestFactory): self {
        $this->requestFactory = $requestFactory;
        return $this;
    }

    public function withKnownHosts(string $knownHosts): self {
        $this->keyscan = new FileKeyscan($knownHosts, strict: false);
        return $this;
    }

    public function withKnownHostsFile(string $file): self {
        return $this->withKnownHosts(
            \file_get_contents($file) ?: throw new \RuntimeException("Failed to read file $file"),
        );
    }

    public function withKeyscan(Keyscan $keyscan): self {
        $this->keyscan = $keyscan;
        return $this;
    }

    public function useRealtimeSshKeyscan(): self {
        $this->keyscan = new ShellExecKeyscan();
        return $this;
    }

    public function build(): Validator {
        return new Validator(
            publicKeyRepository: $this->keyRepository ?? $this->standardKeyRepository(),
        );
    }

    public function standardKeyRepository(): StandardKeyRepository {
        $keyscan = $this->keyscan;
        if ($this->cache !== null) {
            $keyscan = new CachedKeyscan($keyscan, $this->cache);
        }

        return new StandardKeyRepository(
            github: new GithubKeyRepository($this->httpClient, $this->requestFactory),
            ssl: new HttpsCertificateRepository(),
            hostKeyscan: $keyscan,
        );
    }
}
