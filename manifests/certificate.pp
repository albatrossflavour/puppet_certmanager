# @summary Manages one certificate, from issuance through to renewal.
#
# The resource you actually declare. Resolves the issuer configuration,
# plants a bootstrap placeholder so dependent services can start before the
# real certificate exists, and hands the issuance itself to the
# `certmanager_certificate` resource.
#
# @param ensure
#   `present` issues and renews. `absent` revokes with the CA, and deletes
#   the files only if `purge` is also set.
#
# @param issuer
#   Which issuer instance signs this certificate. Defaults to
#   `certmanager::default_issuer`.
#
# @param common_name
#   Subject common name. Defaults to the resource title, which is what you
#   want unless the title is a nickname rather than a hostname.
#
# @param san
#   Additional DNS names. The common name is added automatically, so there
#   is no need to repeat it here.
#
# @param key_type
#   Private key algorithm and size. Changing it reissues the certificate.
#
# @param renew_before_days
#   Days before expiry at which renewal is attempted. The default of 30 is
#   Let's Encrypt's own recommendation and leaves a fortnight of failed
#   runs before anything actually breaks.
#
# @param challenge
#   ACME challenge type, overriding the issuer's default. `dns-01` is the
#   only one that issues wildcards and the only one that does not need the
#   host reachable from the internet.
#
# @param webroot
#   Document root for `http-01`, overriding the issuer's default.
#
# @param subject
#   Additional subject components (O, OU, C, ST, L). Public CAs ignore most
#   of these; DigiCert takes them from the organisation record instead.
#
# @param pkcs12_password
#   Password for the PKCS#12 bundle. Omit and no bundle is generated, which
#   is the right answer unless something downstream wants a keystore.
#
# @param bootstrap
#   Whether to plant a self-signed placeholder when the store is empty.
#   Leave this on unless you validate through DNS and nothing depends on
#   the certificate file existing before first issuance.
#
# @param bootstrap_validity_days
#   How long the placeholder is valid for. Short on purpose: a placeholder
#   nobody noticed should set off an alert in a fortnight, not serve
#   production for a year.
#
# @param purge
#   Whether `ensure => absent` deletes the key material as well as revoking
#   it. Off by default, because removing a certificate from a manifest is
#   usually a refactor and losing the key to one is not recoverable.
#
# @param force_renewal
#   Reissue on the next run regardless of the renewal window. Not
#   idempotent, by definition. Use the `certmanager::renew` task instead
#   unless you genuinely want this in a manifest.
#
# @param revocation_reason
#   Reason passed to the CA on revocation.
#
# @example A wildcard through DNS validation
#   certmanager::certificate { 'star.example.com':
#     issuer      => 'letsencrypt',
#     common_name => '*.example.com',
#     san         => ['example.com'],
#     challenge   => 'dns-01',
#   }
#
# @example A DigiCert certificate for the thing the auditors care about
#   certmanager::certificate { 'payments.example.com':
#     issuer            => 'digicert',
#     san               => ['payments-api.example.com'],
#     key_type          => 'rsa-3072',
#     renew_before_days => 45,
#   }
define certmanager::certificate (
  Enum['present', 'absent']     $ensure                  = 'present',
  Optional[Certmanager::Issuer] $issuer                  = undef,
  Optional[Certmanager::Dnsname] $common_name            = undef,
  Array[Certmanager::Dnsname]   $san                     = [],
  Certmanager::Keytype          $key_type                = 'ecdsa-p256',
  Integer[1, 365]               $renew_before_days       = 30,
  Optional[Certmanager::Challenge] $challenge            = undef,
  Optional[Stdlib::Absolutepath]   $webroot              = undef,
  Hash[Enum['O', 'OU', 'C', 'ST', 'L'], String[1]] $subject = {},
  Optional[Certmanager::Secret] $pkcs12_password         = undef,
  Boolean                       $bootstrap               = true,
  Integer[1, 3650]              $bootstrap_validity_days = 30,
  Boolean                       $purge                   = false,
  Boolean                       $force_renewal           = false,
  Optional[String[1]]           $revocation_reason       = undef,
) {
  include certmanager

  $certname = $title
  $resolved_issuer = pick_default($issuer, $certmanager::default_issuer, undef)

  if !$resolved_issuer {
    fail("certmanager::certificate[${certname}]: no issuer given and certmanager::default_issuer is unset")
  }

  $issuer_config = $certmanager::issuers[$resolved_issuer]

  if !$issuer_config {
    $known = join(keys($certmanager::issuers), ', ')
    fail("certmanager::certificate[${certname}]: issuer '${resolved_issuer}' is not declared in certmanager::issuers (have: ${known})")
  }

  $cn = pick($common_name, $certname)

  # dns-01 is the only challenge a public CA will issue a wildcard through.
  # Catching this at compile time beats catching it after certbot has spent
  # two minutes failing validation.
  $wildcards = ([$cn] + $san).filter |$name| { $name =~ /^\*\./ }
  $effective_challenge = pick_default($challenge, $issuer_config['challenge'], 'http-01')

  if !empty($wildcards) and $issuer_config['backend'] == 'acme' and $effective_challenge != 'dns-01' {
    fail("certmanager::certificate[${certname}]: wildcard names ${join($wildcards, ', ')} need challenge => 'dns-01', got '${effective_challenge}'")
  }

  if $ensure == 'present' and $bootstrap and $issuer_config['backend'] != 'selfsigned' {
    certmanager_placeholder { $certname:
      ensure        => present,
      common_name   => $cn,
      san           => $san,
      key_type      => $key_type,
      validity_days => $bootstrap_validity_days,
      subject       => $subject,
    }

    Certmanager_placeholder[$certname] -> Certmanager_certificate[$certname]
  }

  certmanager_certificate { $certname:
    ensure            => $ensure,
    issuer            => $resolved_issuer,
    issuer_config     => $issuer_config,
    common_name       => $cn,
    san               => $san,
    key_type          => $key_type,
    renew_before_days => $renew_before_days,
    challenge         => $challenge,
    webroot           => $webroot,
    subject           => $subject,
    pkcs12_password   => $pkcs12_password,
    force_renewal     => $force_renewal,
    revocation_reason => $revocation_reason,
    purge_on_absent   => $purge,
  }

  file { "${certmanager::hook_dir}/${certname}":
    ensure => directory,
    owner  => $certmanager::owner,
    group  => $certmanager::group,
    mode   => '0755',
  }

  Class['certmanager::config'] -> Certmanager::Certificate[$certname]
  File["${certmanager::hook_dir}/${certname}"] -> Certmanager_certificate[$certname]
}
