<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;


final class Point{
    /**
     * @link https://secg.org/sec1-v2.pdf#subsubsection.2.3.3
     */
    private const UNCOMPRESSED = "\x04";

    public function __construct(
        private string $x,
        private string $y,
    ) {
    }

    public function uncompressed(): string {
        return self::UNCOMPRESSED.$this->x.$this->y;
    }
}
