<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Der;

final readonly class Nothing extends DataStructure {
    public function __construct() {
        parent::__construct("", type: 0x05);
    }
}
