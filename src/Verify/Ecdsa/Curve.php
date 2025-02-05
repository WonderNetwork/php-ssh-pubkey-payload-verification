<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Verify\Ecdsa;

interface Curve {
    public const ECDP_VER_1 = "\x01";

    public function prime(): string;
    public function a(): string;
    public function b(): string;
    public function generator(): Point;
    public function order(): string;
    public function cofactor(): string;
    public function seed(): string;
}
