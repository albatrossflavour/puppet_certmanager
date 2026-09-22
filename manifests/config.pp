# @summary Creates the certificate store and writes the scan configuration.
#
# Private. Included by `certmanager`.
#
# @api private
class certmanager::config {
  assert_private()

  $owner = $certmanager::owner
  $group = $certmanager::group

  # The store itself is world readable: certificates are public documents
  # and half the point of a canonical layout is that anything can find them.
  # The private files inside are written 0600 by the store, not by Puppet,
  # because Puppet never sees the key material.
  file { [$certmanager::root_dir, $certmanager::store_dir, $certmanager::hook_dir, $certmanager::cache_dir]:
    ensure => directory,
    owner  => $owner,
    group  => $group,
    mode   => '0755',
  }

  # Working state and credentials are a different matter. certbot refuses to
  # use a DNS credentials file that is group readable, which is a nuisance
  # exactly once and correct every time after.
  file { [$certmanager::state_dir, $certmanager::credential_dir]:
    ensure => directory,
    owner  => $owner,
    group  => $group,
    mode   => '0700',
  }

  $scan_config = {
    'scan_directories'       => $certmanager::scan_directories,
    'scan_recursive'         => $certmanager::scan_recursive,
    'ignore_ca_certificates' => $certmanager::ignore_ca_certificates,
    'warn_days'              => $certmanager::warn_days,
    'critical_days'          => $certmanager::critical_days,
  }

  file { "${certmanager::cache_dir}/scan.json":
    ensure  => file,
    owner   => $owner,
    group   => $group,
    mode    => '0644',
    content => stdlib::to_json_pretty($scan_config),
  }

  # Credential files for ACME issuers using a DNS plugin. Written here
  # rather than in the issuer backend so Puppet owns the file and its
  # permissions, and so a changed credential triggers nothing more
  # dramatic than a file update.
  $certmanager::issuers.each |$name, $config| {
    if $config['backend'] == 'acme' and $config['dns_credentials'] {
      file { "${certmanager::credential_dir}/${name}.ini":
        ensure    => file,
        owner     => $owner,
        group     => $group,
        mode      => '0600',
        content   => $config['dns_credentials'],
        show_diff => false,
      }
    }
  }
}
