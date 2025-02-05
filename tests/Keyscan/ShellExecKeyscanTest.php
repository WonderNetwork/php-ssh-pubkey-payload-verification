<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use PHPUnit\Framework\TestCase;

class ShellExecKeyscanTest extends TestCase {
    public function test(): void {
        $actual = null;
        $spy = function (string $command) use (&$actual) {
            $actual .= $command;
            return "";
        };

        $sut = new ShellExecKeyscan($spy);
        $sut->all(new HostSender("example.org", port: 2022));
        self::assertSame("ssh-keyscan -p 2022 'example.org'", $actual);
    }
}
