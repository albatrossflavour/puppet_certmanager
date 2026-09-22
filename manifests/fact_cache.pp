# @summary Keeps the cache behind the `certmanager` fact up to date.
#
# The fact reads a cache rather than parsing certificates on every Puppet
# run. A host with a few hundred certificates in its scan directories would
# otherwise add seconds to each run, and expiry data changes on a scale of
# days, not minutes.
#
# The cache is rebuilt from three places: this schedule, the ACME deploy
# hook when a certificate renews out of band, and the provider itself
# whenever it issues something.
#
# Private. Included by `certmanager`.
#
# @api private
class certmanager::fact_cache {
  assert_private()

  # Pluginsync drops the module's lib/ here on the agent, which is what the
  # scripts need on their load path. Compiling this in rather than guessing
  # at runtime means a non-standard vardir just works.
  $libdir = "${facts['puppet_vardir']}/lib"

  $script = "${certmanager::state_dir}/refresh_facts.rb"

  file { $script:
    ensure  => file,
    owner   => $certmanager::owner,
    group   => $certmanager::group,
    mode    => '0700',
    content => epp("${module_name}/refresh_facts.rb.epp", {
        'libdir'    => $libdir,
        'root_dir'  => $certmanager::root_dir,
        'ruby_path' => $certmanager::ruby_path,
    }),
  }

  $has_acme = !empty($certmanager::issuers.filter |$_name, $config| { $config['backend'] == 'acme' })

  if $has_acme and $facts['os']['family'] != 'windows' {
    $certbot_config_dir = $certmanager::issuers.reduce('/etc/letsencrypt') |$memo, $entry| {
      pick_default($entry[1]['config_dir'], $memo)
    }

    $hook_dir = "${certbot_config_dir}/renewal-hooks/deploy"

    # certbot creates these itself on first use, but the hook needs to be
    # in place before the first renewal, which may well be before certbot
    # has ever run here.
    file { [$certbot_config_dir, "${certbot_config_dir}/renewal-hooks", $hook_dir]:
      ensure => directory,
      owner  => 'root',
      mode   => '0755',
    }

    file { "${hook_dir}/certmanager":
      ensure  => file,
      owner   => 'root',
      mode    => '0755',
      content => epp("${module_name}/acme-deploy-hook.rb.epp", {
          'libdir'    => $libdir,
          'root_dir'  => $certmanager::root_dir,
          'ruby_path' => $certmanager::ruby_path,
      }),
    }
  }

  if $certmanager::manage_fact_refresh {
    if $facts['os']['family'] == 'windows' {
      scheduled_task { 'certmanager fact cache':
        ensure    => present,
        enabled   => true,
        command   => $certmanager::ruby_path,
        arguments => $script,
        user      => 'system',
        trigger   => [{
            'schedule'   => 'daily',
            'start_time' => sprintf('%02d:%02d', $certmanager::refresh_hour, $certmanager::refresh_minute),
        }],
      }
    } else {
      cron { 'certmanager fact cache':
        ensure  => present,
        command => "${certmanager::ruby_path} ${script}",
        user    => 'root',
        hour    => $certmanager::refresh_hour,
        minute  => $certmanager::refresh_minute,
      }
    }
  }
}
