<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Signature;

final readonly class Parser {
    /**
     * @throws ParserException
     */
    public function parse(string $input): OpenSSHContainer {
        $buffer = BinaryBuffer::of(
            ParserSteps::of(
                $input,
                Wrapper::unwrap(...),
                Base64Decoder::decode(...),
                MagicPreamble::validateAndDiscard(...),
                SignatureVersion::validateAndDiscard(...),
            ),
        );

        $publicKey = $buffer->parse();
        $namespace = $buffer->readString();
        $reserved = $buffer->readString();
        $hashAlgorithm = $buffer->readString();
        $signature = $buffer->parse();

        return new OpenSSHContainer(
            publicKey: PubkeyParser::parse($publicKey),
            namespace: $namespace,
            reserved: $reserved,
            hashAlgorithm: HashAlgorithm::from($hashAlgorithm),
            signature: SignatureParser::parse($signature),
        );
    }
}
