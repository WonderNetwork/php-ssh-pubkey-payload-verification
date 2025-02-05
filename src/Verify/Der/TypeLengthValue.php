<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

abstract class TypeLengthValue implements DataStructure {
    public function __toString(): string {
        $s = $this->value();
        $len = \strlen($s);

        if ($len < 0x80) {
            return \pack('Ca*a*', $this->type(), \chr($len), $s);
        }

        $data = \dechex($len);
        $data = \pack('H*', (\strlen($data) & 1 ? '0' : '').$data);
        $len = \chr(\strlen($data) | 0x80).$data;

        return \pack('Ca*a*', $this->type(), $len, $s);
    }

    abstract protected function value(): string;
    abstract protected function type(): int;
}
