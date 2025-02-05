<?php
declare(strict_types=1);

namespace WonderNetwork\SshPubkeyPayloadVerification\Keyscan;

use PHPUnit\Framework\TestCase;
use WonderNetwork\SshPubkeyPayloadVerification\Key\Key;

class FileKeyscanTest extends TestCase {
    public function test_standard_port(): void {
        $file = (string) \file_get_contents(__DIR__.'/../Resources/example.org.keyscan');
        $sut = new FileKeyscan($file);
        $actual = $sut->all(new HostSender('example.org', port: 22));
        self::assertEquals(
            [
                new Key(type: 'ssh-rsa', publicKey: 'AAAAB3NzaC1yc2EAAAADAQABAAABgQDBWaW0ram/m0MnBTKWM6l0aJMPwZs7l8wXXkWRaCoFu03T9omEJpGf/ViVnvQ4mgwFnjcNKyh7ISB7nYq04RvbWOd7m8h4AmrAEjkjTvJ9qp+laEYt0sONUGJCzLinEKPE5Gh4+dMXIlsrq77opqVHoiW+B4oqHXJdP2d9TModFNtgzAlEr8FnLeNz8lTx54r5xnuXMmsewRyuh6y0CvunDAwadztHmZpxurd/WDoABCwaUUyH9qqTOt7S25lVlJn+B0gwSFfyq8DG1fOv0/rz1/nvKcMbl60xPFcKCSu8hudxr/okoPzMg388E08Zx1r9q7wPC+dTHbapT7MTFyx+C1WPveIAE6cBIb+zk/4zzwRkqa5O9UNwzn0hGxfwuJIvuWDICeelJTofTKryndecg3VvEujrS+vxTnSSM5UB0ou2CyYfacUFXpGOjouKEefYCDP8EuNrESFsBz5IFpbWerzEVdhgkC4Cytw8sn2FVBzx5vm7AMYLACqnQ1pq3VE='),
                new Key(type: 'ecdsa-sha2-nistp256', publicKey: 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAHGOuQ3Pvona5A4oW0ehDGmPNEkIplg4bqc+QrZDVplZ0v/Ke1onTiS6rRiBo1AGxYG6QEqjci0tovBO7soXJk='),
                new Key(type: 'ssh-ed25519', publicKey: 'AAAAC3NzaC1lZDI1NTE5AAAAIEcyMS/W7k2+eU5TaNLyNXmtkUnKI3G8yIlmhYJVbKaz'),
            ],
            $actual,
        );
    }

    public function test_custom_port(): void {
        $file = (string) \file_get_contents(__DIR__.'/../Resources/127.0.0.1.keyscan');
        $sut = new FileKeyscan($file);
        $actual = $sut->all(new HostSender('127.0.0.1', port: 2022));
        self::assertEquals(
            [
                new Key(type: 'ssh-rsa', publicKey: 'AAAAB3NzaC1yc2EAAAADAQABAAABgQDCbq6VNbCUXTpdBpZeTlCZs2Tfzx9TmVf6fHF1zTrDUEJJyXFGh6x0C58dgwBdQ8eKElpPEDo/RtVGe+Nf+EBgvQwiygoOdBVZi3kZICqJ66ypS42jN5jK58ItKN0/ACHQHfJeKCFoX8Q8bDl82bi0ZOvrYMvVHtebsutYkMl8YUxH4mww8XN5s489y1MHMaJpNkW0E79CA5kPLwGz4s0B8Dr3itNblqv+vgzCOcmq2Gpi1GI2qKetAr6Jx+Vzae4jhvjSuyLNtVDd6bNLgYsyW47+kHb/lFl18wpCWYr93whZu/it6zOz3c5nxhOF13QAGnseuW7HQAPiq/1En7AAva/G0XbumXN3SqTJP6zCtWtIUn9SDe79gMXBUYW76fA10+ZnTdqd5tlA4oARzw0ldTy9Z0slCu6ihEHhYMvUDDVIujXaC4D1MTjo2a5tMv/ZJ3rP4rPuqe/RVrmf3gKynJ23K2l2QIQpXuzS1rkPEk+JQhQ3oCK6rU+cKcnoax8='),
                new Key(type: 'ecdsa-sha2-nistp256', publicKey: 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIt81+txEEfgrYsWQlSu9FXrscLUJdPRbgs3NTboPrUVGiHW/mklvBeHHdRzBaifY0FTWUXuCYGfVVmAEPcdmTQ='),
                new Key(type: 'ssh-ed25519', publicKey: 'AAAAC3NzaC1lZDI1NTE5AAAAION5YFNt2xOVaWNuNvq3co98ZcPaulgHe2tBW8M1MR1m'),
            ],
            $actual,
        );
    }

    public function test_mismatched_entries_can_be_ignored(): void {
        $file = (string) \file_get_contents(__DIR__.'/../Resources/127.0.0.1.keyscan');
        $sut = new FileKeyscan($file, strict: false);
        $actual = $sut->all(new HostSender('not.matching.host.example.org'));
        self::assertEmpty($actual);
    }
}
