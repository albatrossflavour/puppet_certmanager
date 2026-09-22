# frozen_string_literal: true

require 'spec_helper'

describe 'certmanager::consumer' do
  let(:title) { 'nginx-www' }
  let(:pre_condition) do
    <<~PUPPET
      class { 'certmanager':
        default_issuer => 'letsencrypt',
        issuers        => {
          'letsencrypt' => {
            'backend'       => 'acme',
            'directory_url' => 'https://acme-v02.api.letsencrypt.org/directory',
          },
        },
      }
      certmanager::certificate { 'www.example.com': }
      service { 'nginx': ensure => running }
    PUPPET
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      # A let rather than a local: rubocop hoists let declarations above
      # plain assignments, and a local defined afterwards is not in scope
      # inside them.
      let(:windows) { os.start_with?('windows') }
      let(:root) { windows ? 'C:/ProgramData/PuppetLabs/certmanager' : '/etc/certmanager' }
      let(:hook) { "#{root}/hooks/www.example.com/nginx-www#{windows ? '.ps1' : '.sh'}" }

      context 'with a service' do
        let(:params) { { certificate: 'www.example.com', service: 'nginx' } }

        it { is_expected.to compile.with_all_deps }

        it 'writes an executable hook for the out-of-band renewal path' do
          expect(subject).to contain_file(hook).with_ensure('file').with_mode('0755')
        end

        it 'puts a sensible default reload command in the hook' do
          expected = windows ? "Restart-Service -Name 'nginx'" : 'systemctl reload nginx'
          expect(subject).to contain_file(hook).with_content(%r{#{Regexp.escape(expected)}})
        end

        # certbot renews on its own timer with no catalog in sight, so the
        # hook must find the certificate through the store's environment
        # rather than a path baked in at compile time.
        it 'leaves the paths to the store rather than hardcoding them' do
          expect(subject).to contain_file(hook).with_content(%r{CERTMANAGER_FULLCHAIN})
        end

        # This is the Puppet-run path: first issuance, and anything Puppet
        # itself changed.
        it 'notifies the service when the certificate changes' do
          expect(subject).to contain_certmanager_certificate('www.example.com')
            .that_notifies('Service[nginx]')
        end

        # A failed issuance must leave the service running on the
        # placeholder, not skipped entirely, so the ordering comes from the
        # placeholder and only the notification comes from the certificate.
        it 'orders the placeholder before the service' do
          expect(subject).to contain_certmanager_placeholder('www.example.com')
            .that_comes_before('Service[nginx]')
        end
      end

      context 'with extra commands' do
        let(:params) do
          {
            certificate: 'www.example.com',
            service: 'postfix',
            commands: ['install -o postfix -m 0600 "$CERTMANAGER_PRIVKEY" /etc/postfix/tls/key.pem'],
            only_if: 'systemctl is-active --quiet postfix',
          }
        end

        it { is_expected.to compile.with_all_deps }

        it 'runs the extra commands before the reload' do
          reload = windows ? "Restart-Service -Name 'postfix'" : 'systemctl reload postfix'
          expect(subject).to contain_file(hook)
            .with_content(%r{install -o postfix.*#{Regexp.escape(reload)}}m)
        end

        it 'guards the whole thing so a stopped service is not a failed hook' do
          expect(subject).to contain_file(hook).with_content(%r{systemctl is-active --quiet postfix})
        end
      end

      # A consumer for a service some other module manages, or none at all,
      # must not be the thing that fails compilation.
      context 'with a service that is not in the catalog' do
        let(:params) { { certificate: 'www.example.com', service: 'haproxy' } }

        it { is_expected.to compile.with_all_deps }
      end

      context 'with nothing to do' do
        let(:params) { { certificate: 'www.example.com' } }

        it { is_expected.to compile.and_raise_error(%r{nothing to do; set service, reload_command or commands}) }
      end

      context 'with ensure => absent' do
        let(:params) { { certificate: 'www.example.com', service: 'nginx', ensure: 'absent' } }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file(hook).with_ensure('absent') }
      end
    end
  end
end
