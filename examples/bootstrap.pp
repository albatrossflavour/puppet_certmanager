# The first-run deadlock, and how the placeholder breaks it.
#
# nginx will not start without a certificate file. The http-01 challenge
# cannot succeed without a web server answering on port 80. The certificate
# does not exist until the challenge succeeds. Three things, each waiting
# on the other.
#
# certmanager::certificate plants a short-lived self-signed placeholder at
# the canonical path before the real issuer runs, so nginx starts on a
# certificate nobody trusts, the challenge succeeds, and the real
# certificate replaces it.
class { 'certmanager':
  default_issuer => 'letsencrypt',
  issuers        => {
    'letsencrypt' => {
      'backend'       => 'acme',
      'directory_url' => 'https://acme-v02.api.letsencrypt.org/directory',
      'email'         => 'certs@example.com',
    },
  },
}

certmanager::certificate { 'www.example.com':
  san                     => ['example.com'],

  # On by default. Turn it off if you validate through DNS and nothing
  # depends on the file existing before first issuance.
  bootstrap               => true,

  # Short on purpose. A placeholder nobody noticed should set off an alert
  # in a fortnight, not serve production for a year.
  bootstrap_validity_days => 30,
}

certmanager::consumer { 'nginx-www':
  certificate => 'www.example.com',
  service     => 'nginx',
}

# The resulting ordering is deliberate and worth understanding:
#
#   Certmanager_placeholder[www.example.com] -> Service[nginx]
#   Certmanager_certificate[www.example.com] ~> Service[nginx]
#
# The placeholder comes *before* the service, so the service can start at
# all. The certificate only *notifies*, so a failed issuance leaves nginx
# running on the placeholder rather than skipping it and taking the site
# down to fix a certificate problem.
#
# A placeholder still in place shows up in the fact under `placeholders`,
# so an issuance that quietly fails every night does not stay quiet.
