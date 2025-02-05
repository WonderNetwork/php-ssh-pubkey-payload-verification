<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use PHPUnit\Framework\TestCase;

class Base64DecoderTest extends TestCase {
    public function testDecode(): void {
        $message = \random_bytes(16);
        $sut = new Base64Decoder();
        self::assertSame($message, $sut::decode(\base64_encode($message)));
    }
}
