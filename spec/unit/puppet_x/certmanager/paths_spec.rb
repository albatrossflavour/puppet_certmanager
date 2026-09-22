# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/certmanager/paths'

describe PuppetX::Certmanager::Paths, :store do
  subject(:paths) { described_class }

  describe '.root' do
    it 'honours an explicit override, which is what the hook scripts set' do
      expect(paths.root).to eq(ENV.fetch('CERTMANAGER_ROOT'))
    end

    context 'with no override' do
      around(:each) do |example|
        previous = ENV.fetch('CERTMANAGER_ROOT', nil)
        ENV.delete('CERTMANAGER_ROOT')
        example.run
        ENV['CERTMANAGER_ROOT'] = previous
      end

      # Driven through RbConfig, which is what windows? actually reads,
      # rather than stubbing the method under test and proving nothing.
      def with_host_os(value)
        original = RbConfig::CONFIG['host_os']
        RbConfig::CONFIG['host_os'] = value
        yield
      ensure
        RbConfig::CONFIG['host_os'] = original
      end

      it 'uses the POSIX location' do
        with_host_os('linux-gnu') { expect(paths.root).to eq('/etc/certmanager') }
      end

      # Not /etc/certmanager with a drive letter bolted on: ProgramData is
      # where a Windows service is allowed to keep state.
      it 'uses ProgramData on Windows' do
        with_host_os('mingw32') { expect(paths.root).to eq('C:/ProgramData/PuppetLabs/certmanager') }
      end
    end
  end

  describe 'the directories' do
    it 'keeps credentials separate from the store' do
      expect(paths.credential_dir).to eq(File.join(paths.root, 'credentials'))
      expect(paths.credential_dir).not_to start_with(paths.store_dir)
    end

    it 'keeps issuer working state separate from the store' do
      expect(paths.state_dir).to eq(File.join(paths.root, 'state'))
      expect(paths.state_dir).not_to start_with(paths.store_dir)
    end
  end

  describe '.certificate' do
    it 'lays a certificate out under the store' do
      expect(paths.certificate('www.example.com')).to include(
        dir: File.join(paths.store_dir, 'www.example.com'),
        fullchain: File.join(paths.store_dir, 'www.example.com', 'fullchain.pem'),
        privkey: File.join(paths.store_dir, 'www.example.com', 'privkey.pem'),
      )
    end

    # certmanager::path() resolves the store from Hiera and passes it in,
    # because it runs with no catalogue and cannot read the class parameter.
    it 'accepts a store root from a caller that resolved its own' do
      expect(paths.certificate('www.example.com', store: '/srv/certs')[:cert])
        .to eq('/srv/certs/www.example.com/cert.pem')
    end
  end
end
