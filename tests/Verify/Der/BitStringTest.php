<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

use PHPUnit\Framework\TestCase;

class BitStringTest extends TestCase {
    public function testOfPositive(): void {
        $randomBytes = \random_bytes(16);
        $sut = BitString::ofPositive($randomBytes);
        self::assertSame(
            \bin2hex("\x03\x11\x00".$randomBytes),
            \bin2hex((string) $sut),
        );
    }
}
