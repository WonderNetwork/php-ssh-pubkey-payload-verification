<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use PHPUnit\Framework\TestCase;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyMother;

class OpenSSHContainerTest extends TestCase {
    public function test(): void {
        $sut = new OpenSSHContainer(
            publicKey: KeyMother::some(),
            namespace: "",
            reserved: "",
            hashAlgorithm: new HashAlgorithm('sha256'),
            signature: SignatureMother::some(),
        );
        // snapshot test
        self::assertSame(
            \bin2hex(\base64_decode(\implode([
                "U1NIU0lHAAAAAAAAAAAAAAAGc2hhMjU2AAAAILoH",
                "M1HsMfJwPLMaXPQuIzDrsLM45Inkl7daOr7e0OHN",
            ]))),
            \bin2hex($sut->createSigningPayload("Frank Sobotka for secretary-treasurer")),
        );
    }
}
