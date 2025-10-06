<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Github;

final readonly class GithubUserSender {
    public function __construct(public string $username) {
    }
}
