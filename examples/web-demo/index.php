#!/usr/bin/env php
<?php

use WonderNetwork\SshPubkeyPayloadVerification\ValidatorBuilder;
use WonderNetwork\SshPubkeyPayloadVerification\ValidatorException;

require __DIR__.'/../../vendor/autoload.php';

$sender = sprintf("ssh://%s", $_SERVER['REMOTE_ADDR']);
$namespace = $_POST['namespace'];
$message = file_get_contents($_FILES['message']['tmp_name']);
$signature = file_get_contents($_FILES['signature']['tmp_name']);

$validator = ValidatorBuilder::start()
    ->withKnownHostsFile(__DIR__.'/known_hosts')
    ->build();

try {
    $validator->validate($sender, $namespace, $message, $signature);
    printf($message);
} catch (ValidatorException $exception) {
    header('HTTP/1.0 400 Bad Request');
    printf("Error: %s\n", $exception->getMessage());
}
