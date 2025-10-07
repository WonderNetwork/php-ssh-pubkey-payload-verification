<?php

declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use Closure;

final readonly class ParserSteps {
    /**
     * @param string $input
     * @param Closure(string):string ...$steps
     * @return string
     */
    public static function of(string $input, Closure ...$steps): string {
        $value = $input;
        foreach ($steps as $step) {
            $value = $step($value);
        }

        return $value;
    }
}
