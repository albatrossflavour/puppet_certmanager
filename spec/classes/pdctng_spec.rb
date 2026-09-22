# frozen_string_literal: true

require 'spec_helper'

describe 'certmanager::pdctng' do
  on_supported_os.each do |os, os_facts|
    next if os.start_with?('windows') # pdctng's daemon is Linux only

    context "on #{os}" do
      let(:facts) { os_facts }
      let(:pre_condition) { "service { 'pdctng': ensure => running }" }

      let(:collector) { '/etc/puppetlabs/pdctng/collectors.d/certmanager.rb' }
      let(:config) { '/etc/puppetlabs/pdctng/certmanager.json' }

      context 'with defaults' do
        it { is_expected.to compile.with_all_deps }

        it 'installs the collector into pdctng plugin directory' do
          expect(subject).to contain_file(collector)
            .with_ensure('file')
            .with_source('puppet:///modules/certmanager/pdctng/certmanager.rb')
        end

        # The collector treats a missing config file as "switched off", so
        # landing the plugin first gives the daemon a window where it is
        # present and disabled.
        it 'writes the settings before the collector that reads them' do
          expect(subject).to contain_file(config).that_comes_before("File[#{collector}]")
        end

        # The daemon scans the plugin directory at boot, so a new collector
        # does nothing whatsoever until it restarts.
        it 'restarts the daemon when the collector changes' do
          expect(subject).to contain_file(collector).that_notifies('Service[pdctng]')
        end

        it 'restarts the daemon when the settings change' do
          expect(subject).to contain_file(config).that_notifies('Service[pdctng]')
        end

        it 'points at the local PuppetDB over the standard port' do
          expect(subject).to contain_file(config).with_content(%r{"puppetdb_url": "https://.+:8081"})
        end

        it 'uses the node own agent certificate, which PE already trusts' do
          expect(subject).to contain_file(config).with_content(%r{/etc/puppetlabs/puppet/ssl/private_keys/})
        end

        it 'defaults the detail threshold to the renewal window' do
          expect(subject).to contain_file(config).with_content(%r{"detail_within_days": 30})
        end
      end

      context 'with a widened threshold' do
        let(:params) { { detail_within_days: 60 } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file(config).with_content(%r{"detail_within_days": 60}) }
      end

      context 'with a remote PuppetDB' do
        let(:params) { { puppetdb_url: 'https://puppetdb.example.com:8081' } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file(config).with_content(%r{puppetdb\.example\.com}) }
      end

      # A site that has renamed the unit, or runs it under something else.
      context 'with a differently named service' do
        let(:params) { { service: 'pdctng-exporter' } }
        let(:pre_condition) { "service { 'pdctng-exporter': ensure => running }" }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file(collector).that_notifies('Service[pdctng-exporter]') }
      end

      context 'with ensure => absent' do
        let(:params) { { ensure: 'absent' } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file(collector).with_ensure('absent') }
        it { is_expected.to contain_file(config).with_ensure('absent') }
      end
    end
  end
end
