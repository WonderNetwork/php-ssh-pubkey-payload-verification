<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification;

use PHPUnit\Framework\TestCase;

final class ValidatorTest extends TestCase {
    /** @dataProvider signatures */
    public function testValidate(string $signature): void {
        $sut = ValidatorBuilder::start()
            ->withKnownHostsFile(__DIR__.'/Resources/127.0.0.1.keyscan')
            ->build();

        $sut->validate('ssh://127.0.0.1:2022', 'file', "Hello World!\n", $signature);
        $this->expectNotToPerformAssertions();
    }

    public function testFailsWithoutProperPublicKey(): void {
        $signature = \file_get_contents(__DIR__.'/Resources/hello-world.rsa.sig')
            ?: throw new \RuntimeException("Problem reading signature file");
        $sut = ValidatorBuilder::start()
            ->withKnownHostsFile(__DIR__.'/Resources/127.0.0.1-ed25519.keyscan')
            ->build();

        $this->expectException(KeyMismatchException::class);
        $sut->validate('ssh://127.0.0.1:2022', 'file', "Hello World!\n", $signature);
    }

    public function testFailsWhenNamespaceMismatched(): void {
        $signature = \file_get_contents(__DIR__.'/Resources/hello-world.ecdsa.sig')
            ?: throw new \RuntimeException("Problem reading signature file");
        $sut = ValidatorBuilder::start()
            ->withKnownHostsFile(__DIR__.'/Resources/127.0.0.1-ecdsa.keyscan')
            ->build();

        $this->expectException(NamespaceMismatchException::class);
        $sut->validate('ssh://127.0.0.1:2022', 'email', "Hello World!\n", $signature);
    }

    /** @return iterable<mixed> */
    public static function signatures(): iterable {
        yield 'rsa' => [
            \file_get_contents(__DIR__.'/Resources/hello-world.rsa.sig'),
        ];
        yield 'ed25519' => [
            \file_get_contents(__DIR__.'/Resources/hello-world.ed.sig'),
        ];
        yield 'ecdsa' => [
            \file_get_contents(__DIR__.'/Resources/hello-world.ecdsa.sig'),
        ];
    }
}
