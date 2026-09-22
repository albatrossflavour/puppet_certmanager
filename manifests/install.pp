# @summary Installs the ACME client and any DNS plugins the issuers need.
#
# Only installs what the declared issuers actually use. A node with nothing
# but a DigiCert issuer gets no certbot, because DigiCert is a REST API and
# certbot would be dead weight.
#
# Private. Included by `certmanager`.
#
# @api private
class certmanager::install {
  assert_private()

  if !$certmanager::manage_packages {
    return()
  }

  $acme_issuers = $certmanager::issuers.filter |$_name, $config| { $config['backend'] == 'acme' }

  if empty($acme_issuers) {
    return()
  }

  if $facts['os']['family'] == 'windows' {
    if $certmanager::wacs_package {
      package { $certmanager::wacs_package:
        ensure   => present,
        provider => $certmanager::wacs_package_provider,
      }
    }
  } else {
    if $certmanager::certbot_package {
      package { $certmanager::certbot_package:
        ensure => present,
      }
    }

    # One package per distinct plugin, not per issuer: two issuers both
    # validating through Cloudflare need the plugin once.
    $plugins = $acme_issuers.map |$_name, $config| { $config['dns_plugin'] }.filter |$plugin| { $plugin =~ NotUndef }

    if $certmanager::dns_plugin_package_format {
      unique($plugins).each |$plugin| {
        package { regsubst($certmanager::dns_plugin_package_format, '<plugin>', $plugin):
          ensure => present,
        }
      }
    }
  }
}
