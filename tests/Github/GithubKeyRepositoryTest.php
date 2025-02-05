<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Github;

use Http\Discovery\Psr18Client;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

final class GithubKeyRepositoryTest extends TestCase {
    public function test(): void {
        $psr18Client = new Psr18Client();
        $spy = HttpClientSpy::ofPsr18Discovery($psr18Client);

        $sut = new GithubKeyRepository($spy, $psr18Client);
        $actual = $sut->all(new GithubUserSender('mlebkowski'));
        self::assertEquals(
            [
                new Key(type: 'ssh-rsa', publicKey: 'AAAAB3NzaC1yc2EAAAADAQABAAABgQCVc7VlxAiq4CQuj7CIPeB3T7qNworiTBUOxR4mV+C3Z/rmMzqhBGooTGa77ldLfgVDFlVE2cS3FTFzNRQEOEq5hcfpVCXV7stgJvz0J9WdaVYYTPWyuECa8/XvquwrG2XdsDxKnoKe0Qt5dGtNq2uBjTzR3viMvPdDbhoCMh2EMPXNYUDK2UIinE66kD0RcZ9C1DFlmvpOrd7yLy1Ie9d4Ietv7dZpYbUGhZbNbDIN9qBQxoy5Wkw4RNjC2U+rwDazsoo+RTpoC3E72s/mPm7f/Ow8iLY4hMbkpqs4tp/CgCHnT0zhAHzlqna0cZT51iYH+RGkY8tNtpELXnUVLQ7sP6ZwHswQe4E7w6eVhqUl+0aBDOLJEIjKT9LgssikBTR+9aOO/8dePS0sLvJozqtg2xmniNhzJBTnw2ufgFn7T1AuUIOStW3UorF7fG+xLSVcWm4bqnL3wRpEf71dditmjZ673zwT1+qmy/wEXCYyspkm/asUQ0d3nlO/98qoXDE='),
                new Key(type: 'ssh-rsa', publicKey: 'AAAAB3NzaC1yc2EAAAADAQABAAABgQC+kTIbOIv8K2jKDwgGveByqir97jd/YQM7eE2Y3lfx7+V7d/o43W9U4yHLvULASILWg9sf/OrGchncE5CTC6P8OZE6C0PQintRwtqdmUiX5HXIMHJeciI3IJVlSIeOFTbJ0tImJ+nEoqo4i5WJzRrLnloGQx2/Vy4F0wO72Xe/4r8iPd7rLRcJEQEQHssuKKXGZ3AYUc+3VNnzkUtPFc33TdrzgTp1r+4JqJzrDy8UyPTLZlPUdpmIcyag9s+oyqPoDEKWYFiY/VEWnJl5OyAjHdkfwmtMKwpXEG5dEgzbqPD9kZl4YHu/2Ypd5EI3OLqcpAdyntSWrsOUZw+fPbBEYdfhSBszd58lMjXfqZHfJf6Fn8NOKjOtRikRr3aonUrLH6zoulVLqXI44M6sFf5/fvMFon0sB8sNwlJ0UZVx04Aw2S37cy911qMUjvG6U3ARNxdR2os9uJhWxwKL/9393k+7mFonW6gFTH0C2pas8Eyjywd3hXE228YK5VZucS0='),
                new Key(type: 'ssh-rsa', publicKey: 'AAAAB3NzaC1yc2EAAAADAQABAAABgQDD3XLfjEcIssvopjl1AnKq050NLWrjHa4thW0MV71NteAiuh1xKmIGlf40gWu+/LUpUbHCkNglSqaIDSvUML+NfxuLCV5/n9ZI3gwn7YbxJ37vanZFAMMs+jUMty1UnjkK7AZCqyF6NOQCHzAJzeGmH5HxyGDyZciQ/Rx9MeMdqWI4zpospoxLnx4sw7DqiMauINwYL7FR4gbzMroGpVXdrAfi5sfRursxvA0sGklRFf0Qe7hnbPC2Oqt7LlzmjK56SMqOJyhxWZIz2J+E9Y2HgNi8Up2S2SCFkkcwSc7idVcImpuCD5mgvSE857bJH9ew/kBxTUf/r6OUCBNgvD81rE31UQfPVBhB9vVkruuNZzCuzEKk+HFesxauR3m9ZaVYzr5nJnT3GTa5S9WI14+xrLIOOJ1Wy8BeaK1ZWScKoUWxYDoGzw/DzofCAM6eu8S/qzC+4+HRp5QEaJ35y8F+AgwDq6CFsCQ+xiPbNYV6zQVF8Xu9qU5Ue+z4zqVGNxM='),
            ],
            $actual,
        );
        self::assertSame(
            $spy->calls,
            ['https://github.com/mlebkowski.keys'],
        );
    }

    public function testHttpClientFailure(): void
    {
        $throwing = new class implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface {
                throw new class extends \Exception implements ClientExceptionInterface {};
            }
        };

        $sut = new GithubKeyRepository($throwing, new Psr18Client());
        $this->expectException(UnableToFetchKeysException::class);
        $sut->all(new GithubUserSender('mlebkowski'));
    }
}
