<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use PHPUnit\Framework\TestCase;

class SignatureVersionTest extends TestCase {
    public function test(): void {
        $randomBytes = \random_bytes(32);
        $sut = new SignatureVersion();
        $actual = $sut::validateAndDiscard("\x00\x00\x00\x01".$randomBytes);
        self::assertSame($randomBytes, $actual);
    }

    public function testFailure(): void {
        $randomBytes = \random_bytes(32);
        $sut = new SignatureVersion();
        $this->expectException(InvalidSignatureVersionException::class);
        $sut::validateAndDiscard("\x00\x00\x00\x02".$randomBytes);
    }
}
