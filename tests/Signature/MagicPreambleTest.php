<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

use PHPUnit\Framework\TestCase;

class MagicPreambleTest extends TestCase {
    public function testSuccess(): void {
        $randomBytes = \random_bytes(32);
        $message = 'SSHSIG'.$randomBytes;
        $actual = MagicPreamble::validateAndDiscard($message);
        self::assertSame($randomBytes, $actual);
    }

    public function testFailure(): void {
        $this->expectException(InvalidPreambleException::class);
        MagicPreamble::validateAndDiscard(\random_bytes(16));
    }
}
