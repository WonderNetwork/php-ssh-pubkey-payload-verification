<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

final class HostSender {
    private const DEFAULT_PORT = 22;
    public function __construct(
        private string $host,
        private int $port = self::DEFAULT_PORT,
    ) {
    }

    public function host(): string {
        return $this->host;
    }

    public function port(): int {
        return $this->port;
    }

    public function prefix(): string {
        return $this->hasDefaultPort() ? $this->host : \sprintf('[%s]:%d', $this->host, $this->port);
    }

    private function hasDefaultPort(): bool {
        return $this->port === self::DEFAULT_PORT;
    }
}
