<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

use PHPUnit\Framework\TestCase;

class SubjectPublicKeyInfoTest extends TestCase {
    public function testSnapshot(): void {
        $sut = new SubjectPublicKeyInfo();
        self::assertSame(
            \bin2hex(\base64_decode(\implode([
                'MIIBDDCCAQMGByqGSM49AgEwgfcCAQEwLAYHKo',
                'ZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA',
                '////////////////MFsEIP////8AAAABAAAAAA',
                'AAAAAAAAAA///////////////8BCBaxjXYqjqT',
                '57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAM',
                'SdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEs',
                'Qkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40',
                'Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R',
                '9QIhAP////8AAAAA//////////+85vqtpxeehP',
                'O5ysL8YyVRAgEBAwMANDI=',
            ]))),
            \bin2hex((string) $sut::of(new NistP256(), "42")),
        );
    }
}
