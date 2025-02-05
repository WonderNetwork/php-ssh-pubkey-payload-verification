<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Https;

use Exception;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyException;

final class CertificateException extends Exception implements KeyException {
}
