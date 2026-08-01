# TOTP

Two-factor authentication codes for PHP. TOTP (RFC 6238) and HOTP (RFC 4226), zero dependencies, verified against the official RFC reference vectors.

Works with Google Authenticator, 1Password, Bitwarden, Authy, and anything else implementing the standard.

## Features

- ✅ **RFC-verified** — every vector from RFC 6238 Appendix B passes, across SHA-1, SHA-256 and SHA-512.
- 🔐 **Secret generation** — 160-bit secrets from the CSPRNG, base32-encoded and ready to display.
- 📱 **QR enrolment** — builds the `otpauth://` URI authenticator apps scan.
- ⏱️ **Drift tolerance** — configurable verification window for clock skew.
- 🔁 **Replay defence** — `verify_counter()` reports the matching time step so you can reject reuse.
- 🛡️ **Constant-time** — `hash_equals` throughout, and verification checks every candidate step so timing never leaks the drift.
- 🔡 **Forgiving base32** — accepts the spaced, lowercase form users paste out of their app.
- 🚫 **Zero dependencies** — no `ext-gmp`, no `ext-bcmath`, no packages.

## Requirements

PHP 8.5+

## Installation

```bash
composer require sugarmill/totp
```

## Usage

### Enrolment

```php
use SugarMill\Totp\Totp;

$totp   = new Totp();
$secret = $totp->generate_secret();   // store this against the user

$uri = $totp->enrolment_uri( $secret, 'dave@example.com', 'My Store' );
// otpauth://totp/My%20Store:dave%40example.com?secret=…&issuer=My%20Store&…
```

Render `$uri` as a QR code. Show the raw `$secret` alongside it for anyone typing it in by hand.

### Verification

```php
if ( $totp->verify( $submitted_code, $secret ) ) {
    // authenticated
}
```

### Preventing replay

`verify()` accepts a code for its whole window, so an attacker who observes one can reuse it inside that window. To close it, record the counter and refuse anything that isn't newer:

```php
$counter = $totp->verify_counter( $submitted_code, $secret );

if ( null === $counter || $counter <= $user->last_totp_counter ) {
    // rejected: wrong code, or a replay
}

$user->last_totp_counter = $counter;
```

### Countdown

```php
$totp->seconds_remaining();   // 1-30
```

### Configuration

```php
$totp = new Totp(
    digits: 6,                    // 6 is universal; 8 works in fewer apps
    period: 30,                   // seconds per step
    algorithm: Algorithm::SHA1,
);
```

> **Leave the algorithm on SHA-1.** Google Authenticator and several other apps silently ignore the `algorithm` parameter during enrolment and always compute SHA-1 — enrol with SHA-256 and your users get codes that never match. SHA-1's weakness is collision resistance, which HMAC does not rely on; HMAC-SHA1 is sound here.

### Verification window

The default window of 1 accepts the previous and next time step as well as the current one, absorbing about ±30 seconds of drift plus a slow typist. Every extra step widens the period an intercepted code stays usable in, so keep it small.

```php
$totp->verify( $code, $secret, window: 2 );   // ±60s
```

### Deterministic testing

Pass a fixed `timestamp` to freeze the clock:

```php
$totp = new Totp( timestamp: 1234567890 );
$totp->code( $secret );   // '005924'
```

### Recovery codes

The fallback for a lost or wiped phone. Not part of RFC 6238 — a product concern, but a universal companion to TOTP.

```php
use SugarMill\Totp\RecoveryCodes;

// At enrolment
$codes  = RecoveryCodes::generate();          // ['A3K9M-2PQ7X', …] — show once
$hashes = RecoveryCodes::hash_all( $codes );  // store these

// At login
$index = RecoveryCodes::verify( $submitted, $user->recovery_hashes );

if ( null !== $index ) {
    $user->consume_recovery_code( $index );   // single-use — see below
}
```

Three things this gets right that hand-rolled versions usually don't:

- **They're password-equivalent.** A recovery code bypasses the second factor completely, so it's hashed at rest with `password_hash()` and shown exactly once. The hash is slow on purpose — it only runs on the recovery path, which is rare.
- **They're single-use, and that's your job.** Only your database knows what's been spent, so `verify()` returns the *index* of the code that matched. Consume that index and don't pass it in again.
- **They're independent of the TOTP secret.** Deriving them from it would mean one leak compromises both factors.

Codes use Crockford base32, so `I`, `L`, `O` and `U` never appear and a user who writes `O` for `0` off a printed card still gets in:

```php
RecoveryCodes::verify( 'oabcd lefgh', $hashes );   // matches 0ABCD-1EFGH
```

### Base32 on its own

```php
use SugarMill\Totp\Base32;

Base32::encode( random_bytes( 20 ) );
Base32::decode( 'JBSW Y3DP EHPK 3PXP' );   // spaces and case ignored
Base32::is_valid( $user_input );
```

## Testing

```bash
composer install
composer test
```

107 tests. The core of the suite is the RFC 6238 Appendix B table — 18 vectors pinning the algorithm across three hash functions and timestamps from 1970 to 2603. That's why no authenticator app is needed to trust this: a phone proves agreement at one instant, the vectors prove correctness everywhere.

## License

GPL-2.0-or-later
