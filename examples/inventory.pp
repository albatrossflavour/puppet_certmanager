# Finding the certificates nobody put in Puppet.
#
# The one that takes the service down at 2am is almost never the one in
# your manifests. It is the one somebody deployed by hand in 2019 and then
# left the company.
class { 'certmanager':
  # Empty by default, and deliberately so. Pointing this at /etc/ssl/certs
  # finds several hundred CA roots and buries everything that matters.
  scan_directories       => [
    '/etc/pki/tls/certs',
    '/opt/app/ssl',
  ],
  scan_recursive         => true,
  ignore_ca_certificates => true,

  warn_days              => 30,
  critical_days          => 7,
}

# The scan opens .pem, .crt and .cer only, and never reads private keys.
#
# Results land in the certmanager fact, so the estate is a PuppetDB query
# away:
#
#   puppet query 'inventory[certname] { facts.certmanager.expiring_soon ~ ".+" }'
#   puppet query 'inventory[certname] { facts.certmanager.expired ~ ".+" }'
#   puppet query 'inventory[certname] { facts.certmanager.placeholders ~ ".+" }'
#
# Or from a manifest, for something that should fail loudly:
$doomed = certmanager::expiring(7)

unless empty($doomed) {
  notify { "certificates expiring within 7 days: ${join($doomed, ', ')}":
    loglevel => 'warning',
  }
}
