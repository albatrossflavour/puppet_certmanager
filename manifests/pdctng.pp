# @summary
#   Exposes certificate expiry across the estate through pdctng
#
# Installs a collector plugin into pdctng's `collectors.d`, which reads the
# `certmanager` fact out of PuppetDB and publishes it on pdctng's metrics
# endpoint.
#
# Classify this on the node running the pdctng daemon, which is the PE
# primary, not on the nodes holding certificates. The fact travels to
# PuppetDB on its own; this class is only about reading it back out.
#
# Two things have to be true before it does anything. pdctng must have
# `enable_collector_plugins` set, because third-party Ruby running inside
# the daemon is an operator's decision rather than something that arrives
# with a module upgrade. And this class does not set it for you, for the
# same reason.
#
# ### What it publishes, and why so little of it
#
# pdctng caps a plugin at 1000 series and drops the rest, so the shape here
# is decided by that rather than by what would be nice to have. A series per
# node is ten thousand on a real estate; a series per certificate is worse,
# because a node scanning `/etc/pki` can find fifty.
#
# So the estate is summarised in a fixed handful of series that do not grow
# with it, and per-node detail is emitted only for nodes that need looking
# at. That set is small by definition, and if it is not, the truncation is
# the finding.
#
# ```text
# certmanager_nodes_reporting_total
# certmanager_certificates_total{managed}
# certmanager_nodes_total{state}
# certmanager_node_soonest_expiry_days{node,environment}   only inside the threshold
# ```
#
# @param ensure
#   Whether the collector is installed.
#
# @param puppetdb_url
#   PuppetDB, as the pdctng node reaches it. The default is the local
#   instance over the standard port, which is right on a PE primary.
#
# @param detail_within_days
#   How close to expiry a node has to be before it gets its own series.
#   Nodes with an expired certificate, a bootstrap placeholder still in
#   place, or a stale fact cache are always included regardless.
#
# @param collector_dir
#   pdctng's plugin directory, matching `pdctng::plugin_dir` if the site has
#   moved it.
#
# @param config_file
#   Where the collector reads its settings. The collector treats the file's
#   absence as "switched off", so a site can disable it without a Puppet run.
#
# @param ssl_cert
#   Client certificate for PuppetDB. Defaults to the node's own agent
#   certificate, which is what PE already trusts.
#
# @param ssl_key
#   Private key for that certificate.
#
# @param ssl_ca
#   CA bundle used to verify PuppetDB.
#
# @param service
#   pdctng's service, notified when the collector or its settings change.
#   The daemon scans the plugin directory at boot, so a new collector does
#   nothing at all until it restarts. Set `certmanager::pdctng::service: ~`
#   in Hiera where something else owns restarting it.
#
# @example On the PE primary
#   class { 'pdctng':
#     enable_collector_plugins => true,
#   }
#   include certmanager::pdctng
#
# @example Looking further ahead than the default
#   class { 'certmanager::pdctng':
#     detail_within_days => 60,
#   }
class certmanager::pdctng (
  Enum['present', 'absent'] $ensure             = 'present',
  Stdlib::HTTPUrl           $puppetdb_url       = "https://${trusted['certname']}:8081",
  Integer[1, 365]           $detail_within_days = 30,
  Stdlib::Absolutepath      $collector_dir      = '/etc/puppetlabs/pdctng/collectors.d',
  Stdlib::Absolutepath      $config_file        = '/etc/puppetlabs/pdctng/certmanager.json',
  Stdlib::Absolutepath      $ssl_cert           = "/etc/puppetlabs/puppet/ssl/certs/${trusted['certname']}.pem",
  Stdlib::Absolutepath      $ssl_key            = "/etc/puppetlabs/puppet/ssl/private_keys/${trusted['certname']}.pem",
  Stdlib::Absolutepath      $ssl_ca             = '/etc/puppetlabs/puppet/ssl/certs/ca.pem',
  Optional[String[1]]       $service            = undef,
) {
  $settings = {
    'puppetdb_url'       => $puppetdb_url,
    'detail_within_days' => $detail_within_days,
    'ssl_cert'           => $ssl_cert,
    'ssl_key'            => $ssl_key,
    'ssl_ca'             => $ssl_ca,
  }

  $notify_service = $service ? {
    undef   => undef,
    default => Service[$service],
  }

  # Settings first, collector second. The collector treats a missing config
  # file as "switched off", so landing it the other way round gives the
  # daemon a window where the plugin is present and disabled.
  file { $config_file:
    ensure  => stdlib::ensure($ensure, 'file'),
    owner   => 'root',
    mode    => '0644',
    content => stdlib::to_json_pretty($settings),
    notify  => $notify_service,
  }

  file { "${collector_dir}/certmanager.rb":
    ensure  => stdlib::ensure($ensure, 'file'),
    owner   => 'root',
    mode    => '0644',
    source  => "puppet:///modules/${module_name}/pdctng/certmanager.rb",
    require => File[$config_file],
    notify  => $notify_service,
  }
}
