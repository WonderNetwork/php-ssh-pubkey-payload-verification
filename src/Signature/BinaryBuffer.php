<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class BinaryBuffer {
    private int $pos = 0;
    public static function ofBase64(string $publicKey): self {
        return self::of(\base64_decode($publicKey));
    }

    public static function of(string $buffer): self {
        return new self($buffer);
    }

    private function __construct(private string $buffer) {
    }

    public function peakString(): string {
        $len = $this->peakUint32();
        return \substr($this->buffer, $this->pos + 4, $len);
    }

    public function readString(): string {
        $len = $this->readUint32();
        try {
            return \substr($this->buffer, $this->pos, $len);
        } finally {
            $this->pos += $len;
        }
    }

    public function peakUint32(): int {
        [1 => $value] = \unpack("N", $this->buffer, $this->pos)
            ?: throw new \RuntimeException('Unable to read uint32 from buffer');

        return $value;
    }

    public function readUint32(): int {
        try {
            return $this->peakUint32();
        } finally {
            $this->pos += 4;
        }
    }

    public function restOfBuffer(): string {
        return \substr($this->buffer, $this->pos);
    }

    public function parse(): self {
        return new self($this->readString());
    }

    public function eof(): bool {
        return $this->pos >= \strlen($this->buffer);
    }
}
