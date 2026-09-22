# frozen_string_literal: true

require 'puppet/resource_api'

Puppet::ResourceApi.register_type(
  name: 'certmanager_certificate',
  docs: <<~DOC,
    @summary Manages the lifecycle of one X.509 certificate.

    This is the resource that actually talks to a CA. It is not usually
    declared directly: `certmanager::certificate` wraps it, resolves the
    issuer configuration out of Hiera, sets up the store directories and
    wires in the consumers.

    A certificate is not a conventional resource. Whether it is "correct"
    depends on the clock and on the names it carries, not on simple
    presence, so the provider compares four things on every run: the
    certificate exists, it is not inside its renewal window, its SAN list
    matches what was declared, and its key type matches what was declared.
    Any of those failing triggers reissue.

    @example An ACME certificate with two names
      certmanager_certificate { 'www.example.com':
        ensure        => present,
        issuer        => 'letsencrypt',
        issuer_config => $config,
        common_name   => 'www.example.com',
        san           => ['example.com'],
        key_type      => 'ecdsa-p256',
      }
  DOC
  features: ['simple_get_filter'],
  attributes: {
    ensure: {
      type: 'Enum[present, absent]',
      desc: 'Whether the certificate should exist in the store.',
      default: 'present',
    },
    name: {
      type: 'String[1]',
      desc: 'The certificate name. Used as the directory name in the store and as the issuer-side lineage name.',
      behaviour: :namevar,
    },
    certificate_state: {
      type: 'Enum[current, renewal_due, placeholder, missing, unreadable]',
      desc: <<~DESC,
        Whether the certificate on disk is still fit for purpose.

        Always declared as `current`; the provider reports what it actually
        found. This is what makes time-based renewal work: an expiring
        certificate shows as drift in the report rather than silently
        staying "present" until the day it breaks.

        `placeholder` means the bootstrap self-signed certificate is still
        in place and real issuance has not succeeded.
      DESC
      default: 'current',
    },
    san: {
      type: 'Array[String[1]]',
      desc: 'Every DNS name on the certificate, sorted. Adding or removing one triggers reissue.',
      default: [],
    },
    key_type: {
      type: 'Enum[ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-2048, rsa-3072, rsa-4096]',
      desc: 'Private key algorithm and size. Changing it triggers reissue.',
      default: 'ecdsa-p256',
    },
    not_after: {
      type: 'Optional[String]',
      desc: 'Expiry timestamp, ISO 8601 UTC.',
      behaviour: :read_only,
    },
    days_left: {
      type: 'Optional[Integer]',
      desc: 'Whole days until expiry. Negative once expired.',
      behaviour: :read_only,
    },
    serial: {
      type: 'Optional[String]',
      desc: 'Certificate serial number, hex.',
      behaviour: :read_only,
    },
    fingerprint_sha256: {
      type: 'Optional[String]',
      desc: 'SHA-256 fingerprint of the DER encoding.',
      behaviour: :read_only,
    },
    issuer: {
      type: 'String[1]',
      desc: 'Name of the issuer instance that signs this certificate.',
      behaviour: :parameter,
    },
    issuer_config: {
      type: 'Hash',
      desc: 'Resolved configuration for that issuer instance, supplied by the manifest.',
      behaviour: :parameter,
      default: {},
    },
    common_name: {
      type: 'Optional[String[1]]',
      desc: 'Subject common name. Defaults to the resource title.',
      behaviour: :parameter,
    },
    subject: {
      type: 'Hash[String[1], String[1]]',
      desc: 'Additional subject components (O, OU, C, ST, L).',
      behaviour: :parameter,
      default: {},
    },
    renew_before_days: {
      type: 'Integer[1, 365]',
      desc: <<~DESC,
        Days before expiry at which the certificate is considered due for
        renewal. The default of 30 is Let's Encrypt's own recommendation and
        leaves room for a fortnight of failed runs before anything breaks.
      DESC
      behaviour: :parameter,
      default: 30,
    },
    challenge: {
      type: 'Optional[Enum[http-01, dns-01, tls-alpn-01]]',
      desc: 'ACME challenge type, overriding the issuer default. Ignored by non-ACME backends.',
      behaviour: :parameter,
    },
    webroot: {
      type: 'Optional[String[1]]',
      desc: 'Document root for http-01 validation, overriding the issuer default.',
      behaviour: :parameter,
    },
    pkcs12_password: {
      type: 'Optional[Sensitive[String[1]]]',
      desc: 'Password for the PKCS#12 bundle. Omit to skip generating one.',
      behaviour: :parameter,
    },
    force_renewal: {
      type: 'Boolean',
      desc: 'Reissue on the next run regardless of the renewal window. Not idempotent by design; use the task instead.',
      behaviour: :parameter,
      default: false,
    },
    revocation_reason: {
      type: 'Optional[String[1]]',
      desc: 'Reason passed to the CA when revoking.',
      behaviour: :parameter,
    },
    purge_on_absent: {
      type: 'Boolean',
      desc: <<~DESC,
        Whether `ensure => absent` deletes the files from the store as well
        as revoking with the CA. Defaults to false: removing a certificate
        from a manifest is usually a refactor, and deleting the key material
        as a side effect of that is not recoverable.
      DESC
      behaviour: :parameter,
      default: false,
    },
  },
)
