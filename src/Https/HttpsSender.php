<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Https;

final class HttpsSender {
    public function __construct(private string $host, private int $port) {
    }

    public function host(): string {
        return $this->host;
    }

    public function port(): int {
        return $this->port;
    }

    public function sslConnect(): string {
        return sprintf('ssl://%s:%s', $this->host(), $this->port());
    }
}
