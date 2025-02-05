<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final class Parser {
    /**
     * @throws ParserException
     */
    public function parse(string $input): OpenSSHContainer {
        $input = Wrapper::unwrap($input);
        $input = Base64Decoder::decode($input);
        $input = MagicPreamble::validateAndDiscard($input);
        $input = SignatureVersion::validateAndDiscard($input);

        $buffer = BinaryBuffer::of($input);

        $publicKey = $buffer->parse();
        $namespace = $buffer->readString();
        $reserved = $buffer->readString();
        $hashAlgorithm = $buffer->readString();
        $signature = $buffer->parse();

        return new OpenSSHContainer(
            publicKey: PubkeyParser::parse($publicKey),
            namespace: $namespace,
            reserved: $reserved,
            hashAlgorithm: new HashAlgorithm($hashAlgorithm),
            signature: SignatureParser::parse($signature),
        );
    }
}
