<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

use Stringable;

readonly class DataStructure implements Stringable {
    public function __construct(private string $value, private int $type) {
    }

    public function __toString(): string {
        $s = $this->value;
        $len = \strlen($s);

        if ($len < 0x80) {
            return \pack('Ca*a*', $this->type, \chr($len), $s);
        }

        $data = \dechex($len);
        $data = \pack('H*', (\strlen($data) & 1 ? '0' : '').$data);
        $len = \chr(\strlen($data) | 0x80).$data;

        return \pack('Ca*a*', $this->type, $len, $s);
    }
}
