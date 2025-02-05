<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Utilities;

use Closure;

final class Pipeline {
    public static function of(Closure ...$closures): self {
        return new self($closures);
    }

    /** @param Closure[] $closures */
    private function __construct(private array $closures) {
    }

    public function __invoke(mixed $value, int $key): bool {
        return \array_reduce(
            $this->closures,
            static fn (bool $result, callable $fn) => $result && $fn($value, $key),
            initial: true,
        );
    }
}
