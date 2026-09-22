# The same thing declared entirely in data.
#
# `include certmanager` and nothing else. Everything below lives in Hiera,
# which is where it belongs once you have more than one node.
include certmanager

# common.yaml:
#
#   certmanager::default_issuer: 'letsencrypt'
#   certmanager::issuers:
#     letsencrypt:
#       backend: 'acme'
#       directory_url: 'https://acme-v02.api.letsencrypt.org/directory'
#       email: 'certs@example.com'
#       webroot: '/var/www/html'
#
# nodes/web01.example.com.yaml:
#
#   certmanager::certificates:
#     'www.example.com':
#       san:
#         - 'example.com'
#     'shop.example.com':
#       key_type: 'rsa-2048'
#       renew_before_days: 45
#
#   certmanager::consumers:
#     'nginx-www':
#       certificate: 'www.example.com'
#       service: 'nginx'
#     'nginx-shop':
#       certificate: 'shop.example.com'
#       service: 'nginx'
