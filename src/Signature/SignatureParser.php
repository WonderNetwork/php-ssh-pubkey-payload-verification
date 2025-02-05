<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class SignatureParser {
    public static function parse(BinaryBuffer $buffer): Signature {
        $type = $buffer->readString();
        $blob = $buffer->readString();
        if (false === $buffer->eof()) {
            throw new UnexpectedTrailingSignatureDataException();
        }
        return new Signature(type: $type, blob: $blob);
    }
}
