<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

final class KeyscanSpy implements Keyscan {
    public int $called = 0;

    public static function willAlwaysReturn(Key ...$keys): self {
        return new self($keys);
    }

    private function __construct(private array $keys) {
    }

    public function all(HostSender $sender): array {
        $this->called++;
        return $this->keys;
    }
}
