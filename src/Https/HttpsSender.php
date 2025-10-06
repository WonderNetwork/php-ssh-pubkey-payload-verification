<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Https;

final readonly class HttpsSender {
    public function __construct(public string $host, public int $port) {
    }
}
