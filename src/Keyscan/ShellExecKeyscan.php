<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use Closure;

final class ShellExecKeyscan implements Keyscan {
    private Closure $shellExec;

    public function __construct(?Closure $shellExec = null) {
        $this->shellExec = $shellExec ?? static fn (string $command) => \shell_exec($command);
    }

    public function all(HostSender $sender): array {
        $command = \sprintf("ssh-keyscan -p %d %s", $sender->port(), \escapeshellarg($sender->host()));
        $result = ($this->shellExec)($command);
        if (false === \is_string($result)) {
            throw new CommandExecutionFailedException($command);
        }

        return (new FileKeyscan($result))->all($sender);
    }
}
