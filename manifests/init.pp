# @summary Declarative certificate lifecycle management.
#
# Wraps certbot, DigiCert CertCentral and a self-signed issuer behind one
# resource shape, lands everything in one canonical store, reports on it
# through a fact, and wires consuming services in so they reload when a
# certificate changes.
#
# Including this class on its own does nothing except create the store and
# set up the fact cache. Certificates come from `certmanager::certificate`,
# or from the `certificates` parameter if you would rather declare them in
# Hiera.
#
# @param issuers
#   The CAs this node can get certificates from, keyed by an instance name
#   of your choosing. Several instances of the same backend are fine and
#   usually wanted: a staging Let's Encrypt issuer alongside production
#   saves a lot of rate-limit grief.
#
# @param default_issuer
#   Issuer used by certificates that do not name one. Leave unset to force
#   every certificate to be explicit about who signs it.
#
# @param certificates
#   Certificates to declare, in the form accepted by
#   `certmanager::certificate`. Convenient for Hiera-driven nodes.
#
# @param consumers
#   Service wiring to declare, in the form accepted by
#   `certmanager::consumer`.
#
# @param root_dir
#   Base directory for everything this module owns.
#
# @param owner
#   Owner of the store. Certificates are readable by this user only where
#   they contain key material.
#
# @param group
#   Group of the store. Set this to the group your web server runs as if
#   you would rather it read the key directly than have a hook copy it.
#
# @param store_dir
#   The canonical certificate store. Every issuer lands its output here, so
#   consuming configuration points at one predictable path whoever signed
#   the certificate. `certmanager::path()` resolves against this, so moving
#   it in Hiera moves the templates with it.
#
# @param hook_dir
#   Deploy hook scripts, one directory per certificate.
#
# @param state_dir
#   Issuer working state: ACME accounts, DigiCert order records, keys
#   awaiting an order. Mode 0700.
#
# @param credential_dir
#   Credential files written for issuer backends. Mode 0700.
#
# @param cache_dir
#   Where the fact cache lives.
#
# @param manage_packages
#   Whether to install the ACME client. Turn this off if certbot comes from
#   snap, pip or your own package.
#
# @param certbot_package
#   Package providing certbot.
#
# @param certbot_path
#   Path to the certbot executable.
#
# @param wacs_package
#   Package providing win-acme.
#
# @param wacs_path
#   Path to wacs.exe.
#
# @param dns_plugin_package_format
#   Package name pattern for certbot DNS plugins, with `%{plugin}` standing
#   in for the plugin name.
#
# @param manage_fact_refresh
#   Whether to schedule the job that rebuilds the fact cache. The cache is
#   also rebuilt whenever this module issues a certificate, so the schedule
#   exists to catch certificates renewed out of band and certificates this
#   module does not manage.
#
# @param refresh_hour
#   Hour the fact cache refresh runs.
#
# @param refresh_minute
#   Minute the fact cache refresh runs.
#
# @param ruby_path
#   Ruby used by the refresh job. Defaults to the agent's own.
#
# @param scan_directories
#   Directories to search for certificates this module did not issue. This
#   is where most of the value is: it finds the certificate nobody
#   remembers deploying. Empty by default, because pointing it at a trust
#   bundle finds several hundred CA roots and drowns everything else.
#
# @param scan_recursive
#   Whether the scan descends into subdirectories.
#
# @param ignore_ca_certificates
#   Skip self-signed certificates with no SAN, which is what a CA root in a
#   trust bundle looks like.
#
# @param warn_days
#   Days before expiry at which a certificate is listed in `expiring_soon`.
#
# @param critical_days
#   Days before expiry at which a certificate is listed in
#   `expiring_critical`.
#
# @example Let's Encrypt with DNS validation
#   class { 'certmanager':
#     default_issuer => 'letsencrypt',
#     issuers        => {
#       'letsencrypt' => {
#         'backend'                 => 'acme',
#         'directory_url'           => 'https://acme-v02.api.letsencrypt.org/directory',
#         'email'                   => 'certs@example.com',
#         'challenge'               => 'dns-01',
#         'dns_plugin'              => 'cloudflare',
#         'dns_credentials'         => Sensitive('dns_cloudflare_api_token = ...'),
#         'dns_propagation_seconds' => 60,
#       },
#     },
#   }
#
# @example Finding the certificates nobody put in Puppet
#   class { 'certmanager':
#     scan_directories => ['/etc/pki/tls/certs', '/opt/app/ssl'],
#     scan_recursive   => true,
#   }
class certmanager (
  Hash[Certmanager::Issuer, Certmanager::Issuerconfig] $issuers = {},
  Optional[Certmanager::Issuer] $default_issuer                 = undef,
  Hash[Certmanager::Certname, Hash]                   $certificates = {},
  Hash[String[1], Hash]                               $consumers    = {},

  Stdlib::Absolutepath $root_dir       = '/etc/certmanager',
  String[1]            $owner          = 'root',
  Optional[String[1]]  $group          = undef,
  Stdlib::Absolutepath $store_dir      = "${root_dir}/certs",
  Stdlib::Absolutepath $hook_dir       = "${root_dir}/hooks",
  Stdlib::Absolutepath $state_dir      = "${root_dir}/state",
  Stdlib::Absolutepath $credential_dir = "${root_dir}/credentials",
  Stdlib::Absolutepath $cache_dir      = "${root_dir}/cache",

  Boolean             $manage_packages           = true,
  Optional[String[1]] $certbot_package           = undef,
  Optional[String[1]] $certbot_path              = undef,
  Optional[String[1]] $wacs_package              = undef,
  Optional[String[1]] $wacs_path                 = undef,
  Optional[String[1]] $dns_plugin_package_format = undef,

  Boolean              $manage_fact_refresh = true,
  Integer[0, 23]       $refresh_hour        = 3,
  Integer[0, 59]       $refresh_minute      = 17,
  Stdlib::Absolutepath $ruby_path           = '/opt/puppetlabs/puppet/bin/ruby',

  Array[Stdlib::Absolutepath] $scan_directories       = [],
  Boolean                     $scan_recursive         = false,
  Boolean                     $ignore_ca_certificates = true,
  Integer[1, 365]             $warn_days              = 30,
  Integer[1, 365]             $critical_days          = 7,
) {
  if $default_issuer and !($default_issuer in $issuers) {
    fail("certmanager: default_issuer '${default_issuer}' is not present in \$issuers")
  }

  if $critical_days >= $warn_days {
    fail("certmanager: critical_days (${critical_days}) must be less than warn_days (${warn_days})")
  }

  contain certmanager::config
  contain certmanager::install
  contain certmanager::fact_cache

  Class['certmanager::config']
  -> Class['certmanager::install']
  -> Class['certmanager::fact_cache']

  $certificates.each |$title, $params| {
    certmanager::certificate { $title: * => $params }
  }

  $consumers.each |$title, $params| {
    certmanager::consumer { $title: * => $params }
  }
}
