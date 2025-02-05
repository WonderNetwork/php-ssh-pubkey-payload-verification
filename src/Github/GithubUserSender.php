<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Github;

final class GithubUserSender {
    public function __construct(private string $username) {
    }

    public function username(): string {
        return $this->username;
    }
}
