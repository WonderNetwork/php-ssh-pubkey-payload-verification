<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\TraceableAdapter;
use Symfony\Component\Cache\Adapter\TraceableAdapterEvent;
use Symfony\Component\Cache\Psr16Cache;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

class CachedKeyscanTest extends TestCase {
    public function test_only_calls_once(): void {
        $expected = [
            new Key(type: Key::ED25519, publicKey: 'charlie'),
            new Key(type: Key::RSA, publicKey: 'alpha'),
            new Key(type: Key::ECDSA_SHA2_NISTP256, publicKey:  'bravo'),
        ];
        $cacheSpy = new TraceableAdapter(new ArrayAdapter());
        $cache = new Psr16Cache($cacheSpy);
        $keyscanSpy = KeyscanSpy::willAlwaysReturn(...$expected);
        $sut = new CachedKeyscan($keyscanSpy, $cache);

        $sender = new HostSender('127.0.0.1');
        $fresh = $sut->all($sender);
        self::assertEquals($expected, $fresh);
        self::assertEquals($expected, $sut->all($sender));
        self::assertEquals($expected, $sut->all($sender));
        self::assertSame(1, $keyscanSpy->called);

        $calls = \array_count_values(\array_map(
            static fn (TraceableAdapterEvent $event) => $event->name,
            $cacheSpy->getCalls(),
        ));

        self::assertSame(
            [
                'hasItem' => 3,
                'getItem' => 3,
                'save' => 1,
            ],
            $calls,
        );
    }
}
