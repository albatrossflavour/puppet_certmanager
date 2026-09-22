#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

# Rebuild the certificate inventory cache.
#
# The same work the scheduled job does. Worth running by hand after
# deploying certificates outside Puppet, or before reporting on an estate
# where you want today's answer rather than last night's.

require 'json'

$stdin.read
$LOAD_PATH.unshift(File.join(__dir__, '..', 'lib'))

require 'puppet_x/certmanager/inventory'

begin
  inventory = PuppetX::Certmanager::Inventory.build
  path = PuppetX::Certmanager::Inventory.write_cache(inventory)

  puts JSON.generate(
    'status' => 'ok',
    'cache_file' => path,
    'count' => inventory['count'],
    'managed_count' => inventory['managed_count'],
    'expired' => inventory['expired'],
    'expiring_soon' => inventory['expiring_soon'],
    'placeholders' => inventory['placeholders'],
  )
rescue StandardError => e
  puts JSON.generate('_error' => { 'kind' => 'certmanager/refresh-failed', 'msg' => e.message })
  exit 1
end
