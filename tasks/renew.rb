#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

# Renew one certificate now.
#
# For the 3am case where something is about to expire and waiting for the
# next Puppet run is not an option.
#
# Most of what a renewal needs is already on disk: the store records which
# backend issued a certificate and the ACME client holds its own account
# state, so an ACME renewal needs nothing but the certificate's name.
# DigiCert is the exception, because an order needs an API key and that
# quite deliberately does not live on the host.

require 'json'

params = JSON.parse($stdin.read)
$LOAD_PATH.unshift(File.join(__dir__, '..', 'lib'))

require 'open3'
require 'puppet_x/certmanager/inventory'
require 'puppet_x/certmanager/issuer'
require 'puppet_x/certmanager/store'

def fail_with(kind, message, details = {})
  puts JSON.generate('_error' => { 'kind' => "certmanager/#{kind}", 'msg' => message, 'details' => details })
  exit 1
end

# Reconstruct enough of the resource to reissue, from the certificate
# already in the store. The names and key type come from the certificate
# itself, so a renewal cannot quietly change what the certificate covers.
def resource_from(info, metadata, issuer_config)
  {
    name: metadata['name'],
    issuer: metadata['issuer'],
    issuer_config: issuer_config,
    common_name: info['subject'][%r{CN=([^,]+)}, 1],
    san: info['san'],
    key_type: info['key_type'],
    renew_before_days: metadata['renew_before_days'] || 30,
  }
end

name = params['certificate']
store = PuppetX::Certmanager::Store.new(name)

fail_with('unknown-certificate', "#{name} is not in the certmanager store") unless store.exist?

before = store.info
metadata = store.metadata
backend = metadata['backend'] || 'unknown'

begin
  case backend
  when 'acme', 'placeholder'
    # certbot owns the lineage and the account. Let it do the work, then
    # mirror the result: reissuing around it would orphan its renewal
    # config and the next timer run would undo this one.
    # --no-random-sleep-on-renew matters more than it looks. certbot sleeps
    # for a random interval of up to eight minutes on a non-interactive
    # renewal, to spread load across the CA. That is exactly right for its
    # own timer and exactly wrong for a task somebody is running by hand
    # because something is about to expire.
    args = ['certbot', 'renew', '--non-interactive', '--no-random-sleep-on-renew',
            '--cert-name', name]
    args << '--force-renewal' if params['force']

    # stdin_data closes the child's stdin explicitly. A Bolt task's stdin is
    # the parameter pipe, already read to EOF, and handing that to a
    # subprocess is a good way to find out which tools block on it.
    output, status = Open3.capture2e(*args, stdin_data: '')
    fail_with('renewal-failed', "certbot exited #{status.exitstatus}", 'output' => output.strip) unless status.success?

    lineage = File.join(params['config_dir'] || '/etc/letsencrypt', 'live', name)
    store.refresh_from(
      cert: File.join(lineage, 'cert.pem'),
      key: File.join(lineage, 'privkey.pem'),
      chain: File.join(lineage, 'chain.pem'),
    )

  when 'digicert'
    unless params['api_key']
      fail_with('missing-credential',
                'Renewing a DigiCert certificate needs an api_key parameter; the key is not stored on the host')
    end

    config = { 'backend' => 'digicert', 'api_key' => params['api_key'] }
    config['organization_id'] = params['organization_id'] if params['organization_id']
    config['api_url'] = params['api_url'] if params['api_url']

    PuppetX::Certmanager::Issuer.for(name, resource_from(before, metadata, config)).issue

  when 'selfsigned'
    PuppetX::Certmanager::Issuer.for(name, resource_from(before, metadata, { 'backend' => 'selfsigned' })).issue

  else
    fail_with('unknown-backend', "#{name} was recorded with backend '#{backend}', which cannot be renewed here")
  end
rescue PuppetX::Certmanager::Issuer::Base::Error => e
  fail_with('renewal-failed', e.message)
rescue Errno::ENOENT => e
  fail_with('client-missing', e.message)
end

after = store.info
PuppetX::Certmanager::Inventory.write_cache(PuppetX::Certmanager::Inventory.build)

puts JSON.pretty_generate(
  'status' => (before['serial'] == after['serial']) ? 'unchanged' : 'renewed',
  'certificate' => name,
  'backend' => backend,
  'previous_serial' => before['serial'],
  'serial' => after['serial'],
  'not_after' => after['not_after'],
  'days_left' => after['days_left'],
  'consumers' => PuppetX::Certmanager::Inventory.consumers(name),
)
