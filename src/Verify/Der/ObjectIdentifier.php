<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final readonly class ObjectIdentifier extends DataStructure {
    /**
     * @link https://secg.org/sec1-v2.pdf#subsection.C.3
     * @link https://oid-base.com/get/1.2.840.10045.2.1
     */
    public static function ecPublicKey(): self {
        return self::of("\x2a\x86\x48\xce\x3d\x02\x01");
    }

    /**
     * @link https://secg.org/sec1-v2.pdf#subsection.C.1
     * @link https://oid-base.com/get/1.2.840.10045.1.1
     */
    public static function primeField(): self {
        return self::of("\x2a\x86\x48\xce\x3d\x01\x01");
    }

    /**
     * @link https://oid-base.com/get/1.2.840.113549.1.1.1
     */
    public static function rsaEncryption(): self {
        return self::of("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01");
    }

    private static function of(string $value): self {
        return new self($value, type: 0x06);
    }
}
