<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Utilities\Pipeline;

final class FileKeyscan implements Keyscan {
    public function __construct(private string $knownHosts, private bool $strict = true) {
    }

    public function all(HostSender $sender): array {
        $keys = \explode("\n", $this->knownHosts);
        $keys = \array_values(\array_filter(
            $keys,
            Pipeline::of(
                static fn (string $key) => false === \str_starts_with(\trim($key), "#"),
                static fn (string $key) => "" !== \trim($key),
                function (string $key, int $line) use ($sender): bool {
                    [$prefix] = \explode(" ", $key);
                    if ($sender->prefix() !== $prefix) {
                        $this->strict && throw new InvalidKeyscanFileFormatException(
                            expected: $sender->prefix(),
                            actual: $prefix,
                            lineNo: $line,
                        );
                        return false;
                    }
                    return true;
                }
            ),
            mode: ARRAY_FILTER_USE_BOTH,
        ));

        return \array_map(
            static function (string $key) {
                [, $type, $publicKey] = \explode(" ", $key);
                return new Key(type: $type, publicKey: $publicKey);
            },
            $keys,
        );
    }
}
