#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

# Report on the certificates this node knows about.
#
# Reads the fact cache by default, which is what the `certmanager` fact
# reports and therefore what PuppetDB has. Pass `refresh` to rebuild it
# first, which is what you want when you are about to make a decision based
# on the answer.

require 'json'

params = JSON.parse($stdin.read)
$LOAD_PATH.unshift(File.join(__dir__, '..', 'lib'))

require 'puppet_x/certmanager/inventory'
require 'puppet_x/certmanager/paths'

begin
  inventory = if params['refresh']
                built = PuppetX::Certmanager::Inventory.build
                PuppetX::Certmanager::Inventory.write_cache(built)
                built
              else
                PuppetX::Certmanager::Inventory.read_json(PuppetX::Certmanager::Paths.cache_file)
              end

  if inventory.empty?
    puts JSON.generate(
      'status' => 'no_data',
      '_error' => {
        'kind' => 'certmanager/no-cache',
        'msg' => 'No inventory cache on this node. Run the task again with refresh => true.',
        'details' => { 'cache_file' => PuppetX::Certmanager::Paths.cache_file },
      },
    )
    exit 1
  end

  certificates = inventory['certificates'] || {}
  certificates = certificates.select { |_, c| c['managed'] } if params['managed_only']

  certificates = certificates.select { |_, c| c['days_left'].to_i <= params['expiring_within'] } if params['expiring_within']

  puts JSON.pretty_generate(inventory.merge('certificates' => certificates, 'reported' => certificates.size))
rescue StandardError => e
  puts JSON.generate('_error' => { 'kind' => 'certmanager/report-failed', 'msg' => e.message })
  exit 1
end
