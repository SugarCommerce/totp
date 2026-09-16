<?php
declare( strict_types=1 );
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../../bench-lib.php';

use SugarCommerce\Totp\{Totp, Base32, RecoveryCodes};

$totp   = new Totp();
$secret = $totp->generate_secret();
$codes  = RecoveryCodes::generate();
$hashes = RecoveryCodes::hash_all( $codes );

echo "totp\n";
bench( 'code', 100000, static fn() => $totp->code( $secret ) );
bench( 'verify (window 1, miss)', 50000, static fn() => $totp->verify( '000000', $secret ) );
bench( 'base32 decode', 200000, static fn() => Base32::decode( $secret ) );
bench( 'enrolment_uri', 100000, static fn() => $totp->enrolment_uri( $secret, 'a@b.com', 'Store' ) );
echo "\n  recovery codes are password_hash-backed and slow on purpose:\n";
bench( 'recovery verify (10 hashes)', 20, static fn() => RecoveryCodes::verify( $codes[9], $hashes ) );
bench_footer();
