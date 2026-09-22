# @summary Wires a service to a certificate so it picks up renewals.
#
# There are two renewal paths and they need different handling, which is
# why this is one resource doing two jobs rather than two resources.
#
# On a Puppet run, `Certmanager_certificate` notifies the service directly.
# That is what covers first issuance and anything Puppet itself changed.
#
# Between Puppet runs, certbot renews on its own timer and Puppet never
# sees it. So this also writes a deploy hook script, which the ACME backend
# invokes after any out-of-band renewal. Without it a certificate renews
# perfectly and the service carries on serving the old one until the next
# Puppet run happens to notice.
#
# The service relationship uses a collector, so declaring a consumer for a
# service managed in some other module (or not managed at all) does not
# fail compilation.
#
# @param certificate
#   Name of the certificate this service uses, matching the
#   `certmanager::certificate` title.
#
# @param ensure
#   Whether the hook exists.
#
# @param service
#   Service resource to notify on a Puppet-driven change. Omit if nothing
#   in this catalog manages the service.
#
# @param reload_command
#   Command the out-of-band hook runs to make the service pick up the new
#   certificate. Defaults to reloading `service` through systemctl on
#   Linux, or `Restart-Service` on Windows.
#
# @param commands
#   Extra commands the hook runs before the reload. This is where a service
#   that insists on its own copy of the certificate, with its own
#   ownership, gets one.
#
# @param only_if
#   Guard command. The hook exits 0 without doing anything when this is
#   false, so a stopped service does not produce a failed hook that buries
#   the real ones.
#
# @param manage_relationship
#   Whether to wire the Puppet-run ordering and notification. Turn this off
#   if you want to declare the relationships yourself.
#
# @example nginx, the common case
#   certmanager::consumer { 'nginx-www':
#     certificate => 'www.example.com',
#     service     => 'nginx',
#   }
#
# @example A service that wants its own copy of the key
#   certmanager::consumer { 'postfix-mail':
#     certificate    => 'mail.example.com',
#     service        => 'postfix',
#     commands       => [
#       'install -o postfix -g postfix -m 0600 "$CERTMANAGER_PRIVKEY" /etc/postfix/tls/key.pem',
#       'install -o root -g root -m 0644 "$CERTMANAGER_FULLCHAIN" /etc/postfix/tls/cert.pem',
#     ],
#     reload_command => 'systemctl reload postfix',
#     only_if        => 'systemctl is-active --quiet postfix',
#   }
define certmanager::consumer (
  Certmanager::Certname     $certificate,
  Enum['present', 'absent'] $ensure              = 'present',
  Optional[String[1]]       $service             = undef,
  Optional[String[1]]       $reload_command      = undef,
  Array[String[1]]          $commands            = [],
  Optional[String[1]]       $only_if             = undef,
  Boolean                   $manage_relationship = true,
) {
  include certmanager

  $windows = $facts['os']['family'] == 'windows'

  $default_reload = $service ? {
    undef   => undef,
    default => $windows ? {
      true    => "Restart-Service -Name '${service}'",
      default => "systemctl reload ${service}",
    },
  }

  # Not pick_default: it is a 3.x-API function, so an undef argument
  # arrives as an empty string and the "nothing to do" check below silently
  # passes with a single empty command.
  $reload = $reload_command ? {
    undef   => $default_reload,
    default => $reload_command,
  }

  $all_commands = $reload ? {
    undef   => $commands,
    default => $commands + [$reload],
  }

  if empty($all_commands) {
    fail("certmanager::consumer[${title}]: nothing to do; set service, reload_command or commands")
  }

  $extension = $windows ? { true => '.ps1', default => '.sh' }
  $template  = $windows ? { true => 'hook.ps1.epp', default => 'hook.sh.epp' }
  $hook_path = "${certmanager::hook_dir}/${certificate}/${title}${extension}"

  $params = {
    'certificate' => $certificate,
    'consumer'    => $title,
    'commands'    => $all_commands,
    'only_if'     => $only_if,
  }

  file { $hook_path:
    ensure  => stdlib::ensure($ensure, 'file'),
    owner   => $certmanager::owner,
    group   => $certmanager::group,
    mode    => '0755',
    content => epp("${module_name}/${template}", $params),
  }

  if $manage_relationship and $service and $ensure == 'present' {
    # A collector rather than a direct reference: the service may well be
    # managed somewhere this module knows nothing about, and a consumer
    # declaration should not be the thing that fails compilation.
    #
    # The placeholder orders *before* the service so it can start at all on
    # a first run. The certificate only notifies, so a failed issuance
    # leaves the service running on the placeholder rather than skipping
    # it entirely.
    Certmanager_certificate[$certificate] ~> Service <| title == $service |>

    if defined(Certmanager_placeholder[$certificate]) {
      Certmanager_placeholder[$certificate] -> Service <| title == $service |>
    }
  }
}
