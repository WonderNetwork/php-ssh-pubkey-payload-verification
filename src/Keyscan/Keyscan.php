<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyException;

interface Keyscan {
    /**
     * @return Key[]
     * @throws KeyException
     */
    public function all(HostSender $sender): array;
}
