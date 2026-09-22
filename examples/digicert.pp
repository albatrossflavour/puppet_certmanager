# A commercial certificate through DigiCert CertCentral.
#
# Read this one rather than running it. Orders cost money, and depending on
# the product and your organisation's validation state an order can sit
# pending for days waiting on a human at DigiCert.
#
# Three things follow from that. Order state is kept on the host, so Puppet
# running again before validation finishes does not place a second order. A
# pending order is reported and left alone rather than treated as a
# failure. And the private key never leaves the host: Puppet generates it
# and sends a CSR.
class { 'certmanager':
  issuers => {
    'digicert' => {
      'backend'         => 'digicert',
      'api_key'         => Sensitive(lookup('digicert_api_key')),
      'organization_id' => 12345,
      'product_name_id' => 'ssl_securesite_flex',
      'validity_years'  => 1,
      'signature_hash'  => 'sha256',
    },
  },
}

certmanager::certificate { 'payments.example.com':
  issuer            => 'digicert',
  san               => ['payments-api.example.com'],
  key_type          => 'rsa-3072',

  # Longer than the default, because a DigiCert renewal can wait on a human
  # and 30 days is not much runway when it does.
  renew_before_days => 45,

  # Java wants a keystore.
  pkcs12_password   => Sensitive(lookup('payments_keystore_password')),
}
