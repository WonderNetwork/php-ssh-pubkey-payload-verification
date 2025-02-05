<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

/**
 * @link https://neuromancer.sk/std/nist/P-256
 */
final class NistP256 implements Curve {
    public function prime(): string {
        return \implode([
            "\xFF\xFF\xFF\xFF\x00\x00\x00\x01",
            "\x00\x00\x00\x00\x00\x00\x00\x00",
            "\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        ]);
    }

    public function a(): string {
        return \implode([
            "\xFF\xFF\xFF\xFF\x00\x00\x00\x01",
            "\x00\x00\x00\x00\x00\x00\x00\x00",
            "\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC",
        ]);
    }

    public function b(): string {
        return \implode([
            "\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7",
            "\xB3\xEB\xBD\x55\x76\x98\x86\xBC",
            "\x65\x1D\x06\xB0\xCC\x53\xB0\xF6",
            "\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B",
        ]);
    }

    public function generator(): Point {
        return new Point(
            x: \implode([
                "\x6B\x17\xD1\xF2\xE1\x2C\x42\x47",
                "\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2",
                "\x77\x03\x7D\x81\x2D\xEB\x33\xA0",
                "\xF4\xA1\x39\x45\xD8\x98\xC2\x96",
            ]),
            y: \implode([
                "\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B",
                "\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16",
                "\x2B\xCE\x33\x57\x6B\x31\x5E\xCE",
                "\xCB\xB6\x40\x68\x37\xBF\x51\xF5",
            ]),
        );
    }

    public function order(): string {
        return \implode([
            "\xFF\xFF\xFF\xFF\x00\x00\x00\x00",
            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            "\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84",
            "\xF3\xB9\xCA\xC2\xFC\x63\x25\x51",
        ]);
    }

    public function cofactor(): string {
        return "\x01";
    }

    /**
     * @link https://saweis.net/posts/nist-curve-seed-origins.html
     */
    public function seed(): string {
        return implode([
            "\xC4\x9D\x36\x08",
            "\x86\xE7\x04\x93",
            "\x6A\x66\x78\xE1",
            "\x13\x9D\x26\xB7",
            "\x81\x9F\x7E\x90",
        ]);
    }
}
