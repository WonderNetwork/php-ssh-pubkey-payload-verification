<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification;

use RuntimeException;

final class RuntimeValidatorException extends RuntimeException implements ValidatorException {
}
