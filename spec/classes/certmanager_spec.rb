# frozen_string_literal: true

require 'spec_helper'

describe 'certmanager' do
  let(:letsencrypt) do
    {
      'backend' => 'acme',
      'directory_url' => 'https://acme-v02.api.letsencrypt.org/directory',
      'email' => 'certs@example.com',
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      context 'with no issuers' do
        it { is_expected.to compile.with_all_deps }

        it 'creates the store' do
          expect(subject).to contain_file(windows?(os) ? 'C:/ProgramData/PuppetLabs/certmanager/certs' : '/etc/certmanager/certs')
            .with_ensure('directory')
        end

        # Working state holds key material awaiting an order.
        it 'keeps working state off limits to anyone but the owner' do
          next if windows?(os)

          expect(subject).to contain_file('/etc/certmanager/state').with_mode('0700')
        end

        # certbot refuses to use a DNS credentials file anyone else can read.
        it 'keeps credentials off limits to anyone but the owner' do
          next if windows?(os)

          expect(subject).to contain_file('/etc/certmanager/credentials').with_mode('0700')
        end

        # A node with no ACME issuer has no business having certbot on it.
        it 'installs no ACME client' do
          expect(subject).not_to contain_package('certbot')
        end
      end

      context 'with an ACME issuer' do
        let(:params) { { issuers: { 'letsencrypt' => letsencrypt } } }

        it { is_expected.to compile.with_all_deps }

        it 'installs the ACME client for the platform' do
          expect(subject).to contain_package(acme_client(os, os_facts))
        end

        it 'installs the certbot deploy hook so out-of-band renewals reach the store' do
          next if windows?(os)

          expect(subject).to contain_file('/etc/letsencrypt/renewal-hooks/deploy/certmanager').with_mode('0755')
        end

        # win-acme has its own hook mechanism and no /etc/letsencrypt.
        it 'installs no certbot deploy hook on Windows' do
          next unless windows?(os)

          expect(subject).not_to contain_file('/etc/letsencrypt/renewal-hooks/deploy/certmanager')
        end

        it 'schedules the fact cache refresh through cron' do
          next if windows?(os)

          expect(subject).to contain_cron('certmanager fact cache').with_hour(3).with_minute(17)
        end

        it 'schedules the fact cache refresh through the task scheduler on Windows' do
          next unless windows?(os)

          expect(subject).to contain_scheduled_task('certmanager fact cache')
        end
      end

      context 'with a DNS-validating issuer' do
        let(:params) do
          {
            issuers: {
              'letsencrypt' => letsencrypt.merge(
                'challenge' => 'dns-01',
                'dns_plugin' => 'cloudflare',
                'dns_credentials' => sensitive('dns_cloudflare_api_token = hunter2'),
              ),
            },
          }
        end

        it { is_expected.to compile.with_all_deps }

        # certbot refuses to use a credentials file anyone else can read.
        it 'writes the plugin credentials at 0600 and keeps them out of the diff' do
          next if windows?(os)

          expect(subject).to contain_file('/etc/certmanager/credentials/letsencrypt.ini')
            .with_mode('0600')
            .with_show_diff(false)
        end

        it 'installs the plugin package' do
          next if windows?(os)

          expect(subject).to contain_package('python3-certbot-dns-cloudflare')
        end
      end

      context 'with two issuers using the same DNS plugin' do
        let(:params) do
          {
            issuers: {
              'letsencrypt' => letsencrypt.merge('challenge' => 'dns-01', 'dns_plugin' => 'cloudflare'),
              'staging' => letsencrypt.merge(
                'directory_url' => 'https://acme-staging-v02.api.letsencrypt.org/directory',
                'challenge' => 'dns-01',
                'dns_plugin' => 'cloudflare',
              ),
            },
          }
        end

        it { is_expected.to compile.with_all_deps }
      end

      context 'with manage_packages disabled' do
        let(:params) { { issuers: { 'letsencrypt' => letsencrypt }, manage_packages: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_package('certbot') }
      end

      context 'with a default issuer that does not exist' do
        let(:params) { { issuers: { 'letsencrypt' => letsencrypt }, default_issuer: 'typo' } }

        it { is_expected.to compile.and_raise_error(%r{default_issuer 'typo' is not present}) }
      end

      context 'with the alert thresholds the wrong way round' do
        let(:params) { { warn_days: 7, critical_days: 30 } }

        it { is_expected.to compile.and_raise_error(%r{critical_days .* must be less than warn_days}) }
      end

      context 'with certificates declared in data' do
        let(:params) do
          {
            issuers: { 'letsencrypt' => letsencrypt },
            default_issuer: 'letsencrypt',
            certificates: { 'www.example.com' => { 'san' => ['example.com'] } },
          }
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_certmanager__certificate('www.example.com') }
      end
    end
  end

  def windows?(os)
    os.start_with?('windows')
  end

  # win-acme on Windows, certbot everywhere else, except SLES where the
  # package is namespaced under Python 3.
  def acme_client(os, os_facts)
    return 'win-acme' if windows?(os)

    (os_facts[:os]['family'] == 'Suse') ? 'python3-certbot' : 'certbot'
  end
end
