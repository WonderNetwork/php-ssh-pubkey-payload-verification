<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Key;

interface KeyRepository {
    /**
     * @throws KeyException
     */
    public function all(string $sender): KeyCollection;
}
