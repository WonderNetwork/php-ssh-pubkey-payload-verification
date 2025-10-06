<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

final readonly class HostSender {
    private const int DEFAULT_PORT = 22;

    public function __construct(
        public string $host,
        public int $port = self::DEFAULT_PORT,
    ) {
    }

    public function prefix(): string {
        return $this->hasDefaultPort() ? $this->host : \sprintf('[%s]:%d', $this->host, $this->port);
    }

    private function hasDefaultPort(): bool {
        return $this->port === self::DEFAULT_PORT;
    }
}
