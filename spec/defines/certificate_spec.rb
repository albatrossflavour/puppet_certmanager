# frozen_string_literal: true

require 'spec_helper'

describe 'certmanager::certificate' do
  let(:title) { 'www.example.com' }
  let(:pre_condition) do
    <<~PUPPET
      class { 'certmanager':
        default_issuer => 'letsencrypt',
        issuers        => {
          'letsencrypt' => {
            'backend'       => 'acme',
            'directory_url' => 'https://acme-v02.api.letsencrypt.org/directory',
            'email'         => 'certs@example.com',
          },
          'internal' => {
            'backend'       => 'selfsigned',
            'validity_days' => 365,
          },
          'digicert' => {
            'backend'         => 'digicert',
            'api_key'         => Sensitive('hunter2'),
            'organization_id' => 42,
          },
        },
      }
    PUPPET
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:root) { os.start_with?('windows') ? 'C:/ProgramData/PuppetLabs/certmanager' : '/etc/certmanager' }

      context 'with defaults' do
        it { is_expected.to compile.with_all_deps }

        it 'passes the resolved issuer configuration through to the resource' do
          expect(subject).to contain_certmanager_certificate('www.example.com')
            .with_issuer('letsencrypt')
            .with_common_name('www.example.com')
            .with_key_type('ecdsa-p256')
            .with_renew_before_days(30)
        end

        # nginx will not start without a certificate, the challenge cannot
        # succeed without nginx, and the certificate does not exist until
        # the challenge succeeds. The placeholder breaks the loop.
        it 'plants a bootstrap placeholder before attempting issuance' do
          expect(subject).to contain_certmanager_placeholder('www.example.com')
            .that_comes_before('Certmanager_certificate[www.example.com]')
        end

        it 'creates the hook directory before anything can deploy into it' do
          expect(subject).to contain_file("#{root}/hooks/www.example.com")
            .with_ensure('directory')
            .that_comes_before('Certmanager_certificate[www.example.com]')
        end
      end

      # The certificate a CA issues carries the common name in its SAN list
      # as well. Declaring only the extra names means the resource never
      # matches the certificate it just issued, so every run reports drift
      # and reissues. Against a CA with rate limits that is not a cosmetic
      # bug, and no catalogue-only test catches it.
      context 'with additional names' do
        let(:params) { { san: ['example.com', 'shop.example.com'] } }

        it { is_expected.to compile.with_all_deps }

        it 'declares every name that will be on the certificate, not just the extras' do
          expect(subject).to contain_certmanager_certificate('www.example.com')
            .with_san(['example.com', 'shop.example.com', 'www.example.com'])
        end

        it 'gives the placeholder the same names so SNI keeps working during bootstrap' do
          expect(subject).to contain_certmanager_placeholder('www.example.com')
            .with_san(['example.com', 'shop.example.com', 'www.example.com'])
        end
      end

      context 'with a self-signed issuer' do
        let(:params) { { issuer: 'internal' } }

        it { is_expected.to compile.with_all_deps }

        # There is nothing to bootstrap towards: the certificate this issuer
        # produces is the self-signed one.
        it 'skips the placeholder' do
          expect(subject).not_to contain_certmanager_placeholder('www.example.com')
        end
      end

      context 'with bootstrap disabled' do
        let(:params) { { bootstrap: false } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_certmanager_placeholder('www.example.com') }
      end

      context 'with an unknown issuer' do
        let(:params) { { issuer: 'nonesuch' } }

        it 'names the issuers that do exist rather than just refusing' do
          expect(subject).to compile.and_raise_error(%r{issuer 'nonesuch' is not declared.*have: })
        end
      end

      context 'with a wildcard' do
        let(:title) { 'star.example.com' }

        context 'when validated through DNS' do
          let(:params) { { common_name: '*.example.com', san: ['example.com'], challenge: 'dns-01' } }

          it { is_expected.to compile.with_all_deps }
        end

        # Catching this at compile time beats catching it after certbot has
        # spent two minutes failing validation.
        context 'when validated over HTTP' do
          let(:params) { { common_name: '*.example.com', challenge: 'http-01' } }

          it { is_expected.to compile.and_raise_error(%r{wildcard names .* need challenge => 'dns-01'}) }
        end
      end

      context 'with ensure => absent' do
        let(:params) { { ensure: 'absent' } }

        it { is_expected.to compile.with_all_deps }

        # Removing a certificate from a manifest is usually a refactor.
        it 'revokes without deleting the key material unless asked' do
          expect(subject).to contain_certmanager_certificate('www.example.com')
            .with_ensure('absent')
            .with_purge_on_absent(false)
        end

        it 'does not plant a placeholder for a certificate on its way out' do
          expect(subject).not_to contain_certmanager_placeholder('www.example.com')
        end
      end

      context 'with a DigiCert issuer' do
        let(:params) { { issuer: 'digicert', key_type: 'rsa-3072', renew_before_days: 45 } }

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to contain_certmanager_certificate('www.example.com').with_renew_before_days(45) }
      end
    end
  end
end
