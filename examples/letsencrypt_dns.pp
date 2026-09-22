# Let's Encrypt over dns-01.
#
# The only challenge that issues wildcards, and the only one that works for
# a host the internet cannot reach. Both of those come up more often than
# the documentation suggests.
class { 'certmanager':
  default_issuer => 'letsencrypt',
  issuers        => {
    'letsencrypt' => {
      'backend'                 => 'acme',
      'directory_url'           => 'https://acme-v02.api.letsencrypt.org/directory',
      'email'                   => 'certs@example.com',
      'challenge'               => 'dns-01',
      'dns_plugin'              => 'cloudflare',

      # From eyaml. Written 0600, kept out of the diff, never logged.
      'dns_credentials'         => Sensitive(lookup('cloudflare_certbot_ini')),

      # The setting that actually matters. certbot's default assumes the
      # provider's best case, and a slow zone transfer means the CA looks
      # for the record before it exists. Intermittent dns-01 failures are
      # almost always this.
      'dns_propagation_seconds' => 60,
    },
  },
}

certmanager::certificate { 'star.example.com':
  common_name => '*.example.com',
  san         => ['example.com'],
}

# Declaring a wildcard without dns-01 fails at compile time rather than
# after certbot has spent two minutes failing validation.
