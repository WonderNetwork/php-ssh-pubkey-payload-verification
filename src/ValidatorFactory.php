<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification;

final class ValidatorFactory {
    public static function create(): Validator {
        return ValidatorBuilder::start()->build();
    }
}
