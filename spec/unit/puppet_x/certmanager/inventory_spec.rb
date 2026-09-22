# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/certmanager/inventory'
require 'puppet_x/certmanager/store'

describe PuppetX::Certmanager::Inventory, :store do
  subject(:inventory) { described_class }

  def deploy(name, days: 90, backend: 'acme', issuer: 'letsencrypt', san: [])
    cert, key = CertmanagerSpec.certificate(common_name: name, san: san, days: days)
    PuppetX::Certmanager::Store.new(name).deploy(
      cert: cert.to_pem, key: key.to_pem, issuer: issuer, backend: backend,
    )
  end

  def scan_dir
    dir = File.join(ENV.fetch('CERTMANAGER_ROOT'), 'elsewhere')
    FileUtils.mkdir_p(dir)
    dir
  end

  describe '.build' do
    it 'reports certificates in the store as managed' do
      deploy('www.example.com', san: ['example.com'])

      result = inventory.build
      expect(result['certificates']['www.example.com']).to include(
        'managed' => true, 'issuer' => 'letsencrypt', 'backend' => 'acme',
      )
      expect(result['managed_count']).to eq(1)
    end

    it 'finds certificates this module never issued' do
      cert, = CertmanagerSpec.certificate(common_name: 'forgotten.example.com')
      File.write(File.join(scan_dir, 'old.crt'), cert.to_pem)

      result = inventory.build({ 'scan_directories' => [scan_dir] })
      expect(result['certificates']['forgotten.example.com']).to include('managed' => false)
    end

    # The store is authoritative. A stale copy of a managed certificate
    # lying about in /etc/pki must not overwrite what the store says.
    it 'never lets a scanned certificate displace a managed one' do
      deploy('www.example.com', days: 90)

      stale, = CertmanagerSpec.certificate(common_name: 'www.example.com', days: 2)
      File.write(File.join(scan_dir, 'stale.pem'), stale.to_pem)

      result = inventory.build({ 'scan_directories' => [scan_dir] })
      expect(result['certificates']['www.example.com']).to include('managed' => true, 'days_left' => 90)
    end

    it 'skips the store itself when a scan directory happens to contain it' do
      deploy('www.example.com')

      result = inventory.build({ 'scan_directories' => [ENV.fetch('CERTMANAGER_ROOT')], 'scan_recursive' => true })
      expect(result['certificates'].count { |_, c| c['managed'] == false }).to eq(0)
    end

    it 'leaves CA roots out, so a trust bundle does not drown the real certificates' do
      ca_cert, = CertmanagerSpec.ca
      File.write(File.join(scan_dir, 'ca.crt'), ca_cert.to_pem)

      result = inventory.build({ 'scan_directories' => [scan_dir], 'ignore_ca_certificates' => true })
      expect(result['certificates']).to be_empty
    end

    it 'does not open private keys' do
      _, key = CertmanagerSpec.certificate
      File.write(File.join(scan_dir, 'server.key'), key.to_pem)

      expect(inventory.build({ 'scan_directories' => [scan_dir] })['certificates']).to be_empty
    end

    it 'derives consumers from the hook directory' do
      deploy('www.example.com')
      hooks = File.join(PuppetX::Certmanager::Paths.hook_dir, 'www.example.com')
      FileUtils.mkdir_p(hooks)
      FileUtils.touch(File.join(hooks, 'nginx-www.sh'))

      expect(inventory.build['certificates']['www.example.com']['consumers']).to eq(['nginx-www.sh'])
    end
  end

  describe 'the summary' do
    it 'separates critical from merely soon, without listing anything twice' do
      deploy('critical.example.com', days: 3)
      deploy('soon.example.com', days: 20)
      deploy('fine.example.com', days: 200)

      result = inventory.build({ 'warn_days' => 30, 'critical_days' => 7 })

      expect(result['expiring_critical']).to eq(['critical.example.com'])
      expect(result['expiring_soon']).to eq(['soon.example.com'])
    end

    it 'lists an expired certificate as expired rather than as expiring' do
      deploy('gone.example.com', days: -5)

      result = inventory.build
      expect(result['expired']).to eq(['gone.example.com'])
      expect(result['expiring_critical']).to be_empty
      expect(result['expiring_soon']).to be_empty
    end

    it 'flags a certificate still running on its bootstrap placeholder' do
      deploy('stuck.example.com', backend: 'placeholder', issuer: 'letsencrypt')

      expect(inventory.build['placeholders']).to eq(['stuck.example.com'])
    end

    it 'reports the soonest expiry across everything it can see' do
      deploy('a.example.com', days: 90)
      deploy('b.example.com', days: 12)

      expect(inventory.build['soonest_expiry']).to eq(12)
    end
  end

  describe '.write_cache' do
    it 'writes a cache the fact can read' do
      deploy('www.example.com')
      path = inventory.write_cache(inventory.build)

      expect(JSON.parse(File.read(path))['certificates']).to have_key('www.example.com')
      expect('%o' % (File.stat(path).mode & 0o777)).to eq('644')
    end
  end
end
