<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

use PHPUnit\Framework\TestCase;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

class EcdsaPemFormatterTest extends TestCase {
    public function testFormat(): void {
        $key = new Key(
            type: 'ecdsa-sha2-nistp256',
            publicKey:
            <<<EOF
                AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA
                BBBIt81+txEEfgrYsWQlSu9FXrscLUJdPRbgs3NTboPrUVGiHW
                /mklvBeHHdRzBaifY0FTWUXuCYGfVVmAEPcdmTQ=
                EOF,
        );
        $sut = new EcdsaPemFormatter();
        $actual = $sut->format($key);
        self::assertSame(
            <<<EOF
            -----BEGIN PUBLIC KEY-----
            MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA
            AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA////
            ///////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSd
            NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5
            RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA
            //////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABIt81+txEEfgrYsWQlSu9FXr
            scLUJdPRbgs3NTboPrUVGiHW/mklvBeHHdRzBaifY0FTWUXuCYGfVVmAEPcdmTQ=
            -----END PUBLIC KEY-----
            EOF,
            $actual,
        );
    }
}
