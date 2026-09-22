# The smallest useful thing: an internal certificate, no CA, no network.
#
# Worth starting here. It exercises the store, the fact and the consumer
# wiring without needing certbot, credentials or anything reachable from
# the internet, so if this does not work nothing else will either.
class { 'certmanager':
  default_issuer => 'internal',
  issuers        => {
    'internal' => {
      'backend'       => 'selfsigned',
      'validity_days' => 365,
      'subject'       => {
        'O' => 'Example Ltd',
        'C' => 'AU',
      },
    },
  },
}

certmanager::certificate { 'internal.example.com':
  san => ['internal-api.example.com'],
}
