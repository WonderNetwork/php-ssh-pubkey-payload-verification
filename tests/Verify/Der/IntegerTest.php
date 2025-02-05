<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

use PHPUnit\Framework\TestCase;

class IntegerTest extends TestCase {

    /** @dataProvider integers */
    public function testOfPositive(string $prefix, string $expected): void {
        $randomBytes = $prefix.\random_bytes(16);
        $sut = Integer::ofPositive($randomBytes);
        $len = \chr(\strlen($randomBytes.$expected));
        self::assertSame(
            \bin2hex("\x02$len$expected".$randomBytes),
            \bin2hex((string) $sut),
        );
    }

    /** @return iterable<mixed> */
    public static function integers(): iterable {
        yield 'positive' => ["\x50", ""];
        yield 'negative' => ["\x80", "\x00"];
    }
}
