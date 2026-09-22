# Let's Encrypt over http-01, validated through a running web server.
#
# The webroot matters. Without it certbot stands up its own listener on
# port 80, which means stopping nginx to get a certificate for nginx.
# Pointing it at the document root of a server that is already running
# avoids the whole problem.
class { 'certmanager':
  default_issuer => 'letsencrypt',
  issuers        => {
    'letsencrypt' => {
      'backend'       => 'acme',
      'directory_url' => 'https://acme-v02.api.letsencrypt.org/directory',
      'email'         => 'certs@example.com',
      'webroot'       => '/var/www/html',
    },

    # Rate limits are per registered domain and the penalty for tripping
    # one is an hour's lockout, so point at staging while you are still
    # working out what you want.
    'staging'     => {
      'backend'       => 'acme',
      'directory_url' => 'https://acme-staging-v02.api.letsencrypt.org/directory',
      'email'         => 'certs@example.com',
      'webroot'       => '/var/www/html',
    },
  },
}

certmanager::certificate { 'www.example.com':
  san => ['example.com'],
}

certmanager::consumer { 'nginx-www':
  certificate => 'www.example.com',
  service     => 'nginx',
}

# In the vhost template, so the path survives a change of CA:
#
#   ssl_certificate     <%= certmanager::path('www.example.com', 'fullchain') %>;
#   ssl_certificate_key <%= certmanager::path('www.example.com', 'privkey') %>;
