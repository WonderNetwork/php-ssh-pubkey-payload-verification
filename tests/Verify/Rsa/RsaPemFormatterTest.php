<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Rsa;

use PHPUnit\Framework\TestCase;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

final class RsaPemFormatterTest extends TestCase {
    public function testFormat(): void {
        $sut  = new RsaPemFormatter();
        $key = new Key(
            type: Key::RSA,
            publicKey:
                <<<EOF
                AAAAB3NzaC1yc2EAAAADAQABAAABgQDCbq6VNbCUXTpdBpZeTlCZs2Tf
                zx9TmVf6fHF1zTrDUEJJyXFGh6x0C58dgwBdQ8eKElpPEDo/RtVGe+Nf
                +EBgvQwiygoOdBVZi3kZICqJ66ypS42jN5jK58ItKN0/ACHQHfJeKCFo
                X8Q8bDl82bi0ZOvrYMvVHtebsutYkMl8YUxH4mww8XN5s489y1MHMaJp
                NkW0E79CA5kPLwGz4s0B8Dr3itNblqv+vgzCOcmq2Gpi1GI2qKetAr6J
                x+Vzae4jhvjSuyLNtVDd6bNLgYsyW47+kHb/lFl18wpCWYr93whZu/it
                6zOz3c5nxhOF13QAGnseuW7HQAPiq/1En7AAva/G0XbumXN3SqTJP6zC
                tWtIUn9SDe79gMXBUYW76fA10+ZnTdqd5tlA4oARzw0ldTy9Z0slCu6i
                hEHhYMvUDDVIujXaC4D1MTjo2a5tMv/ZJ3rP4rPuqe/RVrmf3gKynJ23
                K2l2QIQpXuzS1rkPEk+JQhQ3oCK6rU+cKcnoax8=
                EOF,
        );

        $actual = $sut->format($key);
        self::assertSame(
            <<<EOF
            -----BEGIN PUBLIC KEY-----
            MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwm6ulTWwlF06XQaWXk5Q
            mbNk388fU5lX+nxxdc06w1BCSclxRoesdAufHYMAXUPHihJaTxA6P0bVRnvjX/hA
            YL0MIsoKDnQVWYt5GSAqieusqUuNozeYyufCLSjdPwAh0B3yXighaF/EPGw5fNm4
            tGTr62DL1R7Xm7LrWJDJfGFMR+JsMPFzebOPPctTBzGiaTZFtBO/QgOZDy8Bs+LN
            AfA694rTW5ar/r4MwjnJqthqYtRiNqinrQK+icflc2nuI4b40rsizbVQ3emzS4GL
            MluO/pB2/5RZdfMKQlmK/d8IWbv4reszs93OZ8YThdd0ABp7Hrlux0AD4qv9RJ+w
            AL2vxtF27plzd0qkyT+swrVrSFJ/Ug3u/YDFwVGFu+nwNdPmZ03anebZQOKAEc8N
            JXU8vWdLJQruooRB4WDL1Aw1SLo12guA9TE46NmubTL/2Sd6z+Kz7qnv0Va5n94C
            spydtytpdkCEKV7s0ta5DxJPiUIUN6Aiuq1PnCnJ6GsfAgMBAAE=
            -----END PUBLIC KEY-----
            EOF,
            $actual,
        );
    }
}
