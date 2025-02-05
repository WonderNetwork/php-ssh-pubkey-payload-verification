# Verify message payloads using publicly available ssh keys

Most of the servers have a public/private ssh key pair available,
so do most of the developers. Machines have their public parts 
available on port 22 (via `ssh-keyscan`) and devs upload theirs
to Github and similar places. How about instead of authorizing
our messages using passwords and tokens, we could just sign them 
using rsa/ecdsa/ed25519 keys we already use for SSH communication,
and let the receiver verify that against publicly available records?

## How it works?

The sender identifies a private key they want to use. This might
be an `/etc/ssh/ssh_host_ecdsa_key`, for which the public counterpart
is available via `ssh-keyscan` to the receiver. For people, their
personal ssh key uploaded to github could be used, as the public
keys of each user are available at `github.com/username.keys`.

> [!NOTE]
> Most of the servers exposing something over HTTP also have
> a HTTPS certificate issued. While this is not strictly in scope
> of this package because that is not a SSH private key, it can
> be easily converted to one, and since the cert is exposed on
> port 443, it is easy to verify by the receivers.

`ssh-keygen` can be used to sign a message (see also 
[`bin/ssh-sign` script][ssh-sign]). Then they can send the payload
with a corresponding `.sig` file to the receiver.

```sh
ssh-keygen -Y sign -f ~/.ssh/id_rsa -n "com.acme.namespace" payload.json
curl --silent \
  --form "payload=@payload.json" \
  --form "signature=@payload.json.sig" \
  --form "username=mlebkowski" \
  https://example.org
```

The receiver in turn needs to determine the sender’s identity.
This could be done explicitly (e.g. by passing their github username
along with the message), or implicitly: by the sender’s IP address.

Then the receiver confirms that the signature used one of the public
keys available for a given sender, and that the signature matches
the message payload. No passwords.

See also [example][demo] for a simple proof of concept.

## Installation

```sh
composer require wondernetwork/ssh-pubkey-payload-verification
```

You will need a `psr/http-client` and `psr/simple-cache` implementations.
Most frameworks will have this for you, but in case you don’t have them,
you can just pick one from the top:

 * [packagist `psr/http-client` implementations][http-client]
 * [packagist `psr/http-factory` implementations][http-factory]
 * [packagist `psr/http-message` implementations][http-message]
 * [packagist `psr/simple-cache` implementations][simple-cache]

## Usage

```php
use WonderNetwork\SshPubkeyPayloadVerification\ValidatorBuilder;

// simples use case:
$validator = ValidatorBuilder::start()->build();

// all available configuration options:
$validator = ValidatorBuilder::start()
    // cache the fetched ssh-keyscans
    ->withCache($simpleCacheAdapter)

    // provide your own httpClient instead of relying on autodiscovery
    // if you’d like to cache calls to github, pass your own caching client
    ->withHttpClient($httpClient)
    ->withHttpMessageFactory($requestFactory)

    // when a request comes in, just execute ssh-keyscan
    // to get all their public keys. This is the default
    ->useRealtimeSshKeyscan()
    // instead of doing keyscan for each sender
    // pass a pre-determined known-hosts contents or filename
    ->withKnownHosts($knownHostsContent)
    ->withKnownHostsFile($knownHostsFilename)
    // replace the whole host keyscan implementation with your own
    ->withSshKeyscan($myFancyKeyscan)

    // replace the `KeyRepository` entirely and provide you own
    // way for getting list of keys of any given sender
    // this allows you to create custom sender types and sources 
    // of their public keys
    ->withCustomKeyRepository()
    ->build();
```

Having the validator, we can now proceed to checking payloads:

```php
use WonderNetwork\SshPubkeyPayloadVerification\Validator;
use WonderNetwork\SshPubkeyPayloadVerification\ValidatorException;

/** @var Validator $validator */
try {
   $validator->validate(
     sender: sprintf("ssh://%s:%d", $_SERVER['REMOTE_ADDR'], 22),
     // alternatives:
     // sender: sprintf("https://%s:%d", $_SERVER['REMOTE_ADDR'], 443),
     // sender: "github://mlebkowski",
     namespace: "something you just need to agree on",
     // deliver it any way you like it
     message: $_POST['message'],
     // deliver it any way you like it:
     signature: $_POST['signature'],
   );
   // good, we can act as if this sender/message are authenticated!
} catch (ValidatorException $e) {
   // bad cookie, we discard the message
   // depending on $e, there might be some interesting context why it failed
}
```

## Security

This solution is based on the same PKI infrastructure and
mathematics behind RSA/ECC as the connection to your bank does.
There are some caveats:

 * The `ssh-keyscan` is over an insecure connection. There are no
    equivalent of HTTPS certificates for SSH connections, so an
    attacker in position to alter your network traffic is able to
    spoof this. Similarly, if the target sender is taken over before
    the receiver had the chance to receive their public key list.

   Consider using a static known hosts file instead, or think about
    implementing a solution that uses HTTPS certificates if that’s
    something your senders have at hand.

 * This does not server as _authorization_ of the sender’s message,
    so you need to do this separately. Nor this secures the 
    communication in any way, so think about transport layer security
    separately (delivering over HTTPS should be enough). This is
    stateless, so it doesn’t prevent replay attacks in any way.

 * There is no revocation mechanism other than manually evicting 
    a key from your cache.

## Cookbook

### Using HTTPS certificates

In order to use a certificate, you need to first convert it’s PEM private
key into a SSH private key. 

```sh
# copy from the place you keep HTTPS certificates
cp /etc/letsencrypt/live/acme.example.org/privkey.pem ssh-signkey.rsa
# limit permissions, or ssh-keyscan will refuse to work with that file
chmod 0600 ssh-signkey.rsa
# rewrite the key in-place (here: without using a passphrase) in OpenSSH format
ssh-keygen -p -N "" -f ssh-signkey.rsa
# use as any other SSH private key
jq -Mcn .valid=true | ssh-keygen -Y sign -n example -f ssh-signkey.rsa
```

[ssh-sign]: bin/ssh-sign
[demo]: ./example/
[http-client]: https://packagist.org/providers/psr/http-client-implementation
[simple-cache]: https://packagist.org/providers/psr/simple-cache-implementation
[http-factory]: https://packagist.org/providers/psr/http-factory-implementation
[http-message]: https://packagist.org/providers/psr/http-message-implementation
