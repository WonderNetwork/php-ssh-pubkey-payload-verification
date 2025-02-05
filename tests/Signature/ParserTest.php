<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use PHPUnit\Framework\TestCase;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

final class ParserTest extends TestCase {
    /** @dataProvider signatures */
    public function test_parse_sample(
        string $sig,
        string $expectedKeyType,
        string $expectedPublicKey,
        string $expectedSignatureType,
        string $expectedSignatureBlob,
    ): void {
        $sample = \file_get_contents(__DIR__ . '/../Resources/'.$sig)
            ?: throw new \RuntimeException("Failed reading $sig file");
        $sut = new Parser();
        $actual = $sut->parse($sample);
        self::assertEquals(
            new OpenSSHContainer(
                publicKey: new Key(type: $expectedKeyType, publicKey: $expectedPublicKey),
                namespace: 'file',
                reserved: '',
                hashAlgorithm: new HashAlgorithm('sha512'),
                signature: new Signature(
                    type: $expectedSignatureType,
                    blob: $expectedSignatureBlob,
                ),
            ),
            $actual,
        );
    }

    /** @return iterable<mixed> */
    public static function signatures(): iterable {
        yield 'rsa' => [
            'hello-world.rsa.sig',
            'ssh-rsa',
            'AAAAB3NzaC1yc2EAAAADAQABAAABgQDCbq6VNbCUXTpdBpZeTlCZs2Tfzx9TmVf6fHF1zTrDUEJJyXFGh6x0C58dgwBdQ8eKElpPEDo/RtVGe+Nf+EBgvQwiygoOdBVZi3kZICqJ66ypS42jN5jK58ItKN0/ACHQHfJeKCFoX8Q8bDl82bi0ZOvrYMvVHtebsutYkMl8YUxH4mww8XN5s489y1MHMaJpNkW0E79CA5kPLwGz4s0B8Dr3itNblqv+vgzCOcmq2Gpi1GI2qKetAr6Jx+Vzae4jhvjSuyLNtVDd6bNLgYsyW47+kHb/lFl18wpCWYr93whZu/it6zOz3c5nxhOF13QAGnseuW7HQAPiq/1En7AAva/G0XbumXN3SqTJP6zCtWtIUn9SDe79gMXBUYW76fA10+ZnTdqd5tlA4oARzw0ldTy9Z0slCu6ihEHhYMvUDDVIujXaC4D1MTjo2a5tMv/ZJ3rP4rPuqe/RVrmf3gKynJ23K2l2QIQpXuzS1rkPEk+JQhQ3oCK6rU+cKcnoax8=',
            'rsa-sha2-512',
            hex2bin('2ca7e68968f68c5768ab9c1c61a79f90f1eadbb5b8d8c63c48b59687f2c41aa76e57bcf8745fcb5faefaf6c8dce22e36b50a672f5bbc65fb79b8de3fdffc161335f0e15b2ed6ac725c7bdf5a45080c0710e547fdff6fb5497142b118a1923982076677dbc912cb291c0606953177863644c86735d63ad5d4baaa91a1352d45925155b6c427af742eabd908b4c68513551963da500563ecea367cb88487dfbfe91954c25a1982be34a24d31f4f933aa7275fa56b5fb1c8240cc0f37e01f4dada2de77ff3250d6ba0cee3e32ee34bd65270a12e0f547b09d3d66fed853c4f8c23bffbc7745a73719779d3e9569430bb615a488638b1311eb0af59cb0ea232ee0c4d1c595a11f793cdcd2823dfad409c865ab4ca1f986190051e9f4f21a2a3c2e1f32ce270244c84340c3d79bf7bf81d455172cffbe86830bf9d9d18b304e63f3a89e3d336c4b9787bce4af251d995c8504d697407b1bd46e94faa436bca98b739dc646c7b4eb5cc4b6f3f3c5ee9c864d53bf302ae85ce2325132e9b9cb7c74d53f'),
        ];
        yield 'ed25519' => [
            'hello-world.ed.sig',
            'ssh-ed25519',
            'AAAAC3NzaC1lZDI1NTE5AAAAION5YFNt2xOVaWNuNvq3co98ZcPaulgHe2tBW8M1MR1m',
            'ssh-ed25519',
            hex2bin('9549585bcf5411fbe395566944f1927c16232c8ed3615ae074cf3cc5d961dc2f6e8700e5bf2bb4f06487aaf1389a4ca9604be873832d451051944bb57a6b810a'),
        ];
        yield 'ecdsa' => [
            'hello-world.ecdsa.sig',
            'ecdsa-sha2-nistp256',
            'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIt81+txEEfgrYsWQlSu9FXrscLUJdPRbgs3NTboPrUVGiHW/mklvBeHHdRzBaifY0FTWUXuCYGfVVmAEPcdmTQ=',
            'ecdsa-sha2-nistp256',
            hex2bin('0000002100c1a5530c50e2b59d5007d3b1e045bc86d96d4f9d52fecc1bdb9ff61d8e4fd30000000021008312eb013656e7b177882b1d2034ab1b91da83dfc5ca3413882f18454275cf73'),
        ];
    }
}
