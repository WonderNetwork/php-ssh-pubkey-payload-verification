<?php
declare(strict_types=1);

use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyCollection;
use WonderNetwork\SshPubkeyPayloadVerification\Key\KeyRepository;
use WonderNetwork\SshPubkeyPayloadVerification\KeyMismatchException;
use WonderNetwork\SshPubkeyPayloadVerification\ValidatorBuilder;

require_once __DIR__ . '/../../vendor/autoload.php';

[, $sender, $namespace, $messageFile] = $argv;

$message = file_get_contents($messageFile);
$signature = file_get_contents($messageFile.'.sig');

function get_keys_from_dns(string $domain, string $hostName): KeyCollection {
    $records = dns_get_record(sprintf('%s.%s', $hostName, $domain), DNS_TXT);
    if (false === $records) {
        return KeyCollection::empty();
    }

    $keys = array_map(
        /** @param array{txt:string} $record */
        static function (array $record) {
            [$type, $key] = explode(' ', $record['txt']);
            return new Key(type: $type, publicKey: $key);
        },
        $records,
    );

    return KeyCollection::of(...$keys);
}

$dnsTxtRepository = new class (ValidatorBuilder::start()->standardKeyRepository()) implements KeyRepository {
    public function __construct(private KeyRepository $standardKeyRepository) {
    }

    public function all(string $sender): KeyCollection {
        $url = parse_url($sender);
        return match ($url['scheme'] ?? null) {
            'dns' => get_keys_from_dns(
                $url['host'] ?? throw new RuntimeException('Host is required'),
                ltrim($url['path'] ?? throw new RuntimeException('Path is required'), '/'),
            ),
            default => $this->standardKeyRepository->all($sender),
        };
    }
};

$validator = ValidatorBuilder::start()
    ->withCustomKeyRepository($dnsTxtRepository)
    ->build();

try {
    $badSender = $sender . '-404';
    $validator->validate($badSender, $namespace, $message, $signature);
} catch (KeyMismatchException $e) {
    if ($e->allowed->isEmpty()) {
        echo "Dummy validation failed as expected, because there are no TXT records ";
        echo "under the $badSender hostname\n";
    } else {
        echo "Unexpected error: {$e->getMessage()}\n";
    }
} catch (\Throwable $e) {
    echo "Unexpected error: {$e->getMessage()}\n";
}

try {
    $validator->validate($sender, $namespace, $message, $signature);
} catch (\Throwable $e) {
    echo "Unexpected error: {$e->getMessage()}\n";
    exit(1);
}
echo "Validation successful\n";
