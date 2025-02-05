<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use Psr\SimpleCache\CacheInterface;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

final class CachedKeyscan implements Keyscan {
    public function __construct(private Keyscan $actual, private CacheInterface $cache) {
    }

    public function all(HostSender $sender): array {
        $key = \sprintf('%s_%d', $sender->host(), $sender->port());
        if ($this->cache->has($key)) {
            $file = $this->cache->get($key);
            if (is_string($file)) {
                return (new FileKeyscan($file))->all($sender);
            }
        }

        $keys = $this->actual->all($sender);
        $this->cache->set($key, $this->toFile($sender, ...$keys));
        return $keys;
    }

    private function toFile(HostSender $sender, Key ...$keys): string {
        $prefix = $sender->prefix();
        return implode("\n", \array_map(
            static fn (Key $key) => \sprintf('%s %s %s', $prefix, $key->type(), $key->publicKey()),
            $keys,
        ));
    }
}
