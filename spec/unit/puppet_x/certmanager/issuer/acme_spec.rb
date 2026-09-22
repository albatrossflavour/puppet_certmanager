# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/certmanager/issuer/acme'

describe PuppetX::Certmanager::Issuer::Acme, :store do
  subject(:issuer) { described_class.new('www.example.com', resource, config) }

  let(:resource) do
    { common_name: 'www.example.com', san: ['example.com'], key_type: 'ecdsa-p256', issuer: 'letsencrypt' }
  end
  # The backend already takes certbot's config directory as an issuer
  # setting, so the tests point it at a scratch directory rather than
  # stubbing the object under test.
  let(:certbot_dir) { Dir.mktmpdir('certbot') }
  let(:lineage_dir) { File.join(certbot_dir, 'live', 'www.example.com') }
  let(:config) do
    {
      'directory_url' => 'https://acme-v02.api.letsencrypt.org/directory',
      'email' => 'certs@example.com',
      'config_dir' => certbot_dir,
    }
  end
  let(:status) { instance_double(Process::Status, success?: true, exitstatus: 0) }

  # Capture the command instead of running it. Asserting the arguments built
  # is the only useful thing a unit test can say about a CLI wrapper.
  def capture_certbot
    captured = nil
    allow(Open3).to receive(:capture2e) do |*args, **_kwargs|
      captured = args
      ['', status]
    end
    yield
    captured
  end

  # Put something where certbot would have left it, so #sync has work to do.
  def stage_lineage(days: 90)
    FileUtils.mkdir_p(lineage_dir)
    ca_cert, ca_key = CertmanagerSpec.ca
    cert, key = CertmanagerSpec.certificate(common_name: 'www.example.com', san: ['example.com'], days: days,
                                            issuer: ca_cert, issuer_key: ca_key)
    File.write(File.join(lineage_dir, 'cert.pem'), cert.to_pem)
    File.write(File.join(lineage_dir, 'privkey.pem'), key.to_pem)
    File.write(File.join(lineage_dir, 'chain.pem'), ca_cert.to_pem)
  end

  after(:each) { FileUtils.rm_rf(certbot_dir) }

  describe '#issue' do
    it 'asks certbot for every declared name' do
      stage_lineage
      args = capture_certbot { issuer.issue }

      expect(args).to include('certonly', '--cert-name', 'www.example.com')
      expect(args.join(' ')).to include('-d example.com').and include('-d www.example.com')
    end

    # Puppet's own stdin, or a Bolt task's parameter pipe, is not something
    # certbot should be able to block on.
    it 'closes the client stdin rather than handing it whatever Puppet had' do
      stage_lineage
      captured = nil
      allow(Open3).to receive(:capture2e) do |*_args, **kwargs|
        captured = kwargs
        ['', status]
      end

      issuer.issue

      expect(captured).to include(stdin_data: '')
    end

    it 'passes the directory URL so a staging issuer really hits staging' do
      stage_lineage
      args = capture_certbot { issuer.issue }

      expect(args).to include('--server', 'https://acme-v02.api.letsencrypt.org/directory')
    end

    # --keep-until-expiring is what makes this idempotent against certbot's
    # own timer: Puppet can ask on every run without burning rate limit.
    it 'tells certbot to leave a certificate that is not due yet alone' do
      stage_lineage
      expect(capture_certbot { issuer.issue }).to include('--keep-until-expiring')
    end

    it 'registers without an email rather than prompting when none is given' do
      stage_lineage
      anonymous = described_class.new('www.example.com', resource, config.except('email'))

      args = capture_certbot { anonymous.issue }
      expect(args).to include('--register-unsafely-without-email')
    end

    context 'with an EC key' do
      it 'names the curve certbot expects, not the one the manifest uses' do
        stage_lineage
        args = capture_certbot { issuer.issue }

        expect(args).to include('--key-type', 'ecdsa', '--elliptic-curve', 'secp256r1')
      end
    end

    context 'with an RSA key' do
      let(:resource) { super().merge(key_type: 'rsa-3072') }

      it 'passes the size across as a separate flag' do
        stage_lineage
        args = capture_certbot { issuer.issue }

        expect(args).to include('--key-type', 'rsa', '--rsa-key-size', '3072')
      end
    end

    context 'with dns-01 validation' do
      let(:config) { super().merge('challenge' => 'dns-01', 'dns_plugin' => 'cloudflare', 'dns_propagation_seconds' => 60) }

      it 'selects the plugin and waits for propagation' do
        stage_lineage
        args = capture_certbot { issuer.issue }

        expect(args).to include('--dns-cloudflare', '--dns-cloudflare-propagation-seconds', '60')
      end

      it 'refuses to run when the issuer forgot to name a plugin' do
        broken = described_class.new('www.example.com', resource, config.except('dns_plugin'))

        expect { broken.issue }
          .to raise_error(PuppetX::Certmanager::Issuer::Base::Error, %r{sets no dns_plugin})
      end
    end

    context 'with a webroot' do
      let(:config) { super().merge('webroot' => '/var/www/html') }

      it 'uses the running web server rather than standing up its own listener' do
        stage_lineage
        args = capture_certbot { issuer.issue }

        expect(args).to include('--webroot', '--webroot-path', '/var/www/html')
        expect(args).not_to include('--standalone')
      end
    end

    it 'reports what certbot actually said when it fails' do
      failed = instance_double(Process::Status, success?: false, exitstatus: 1)
      allow(Open3).to receive(:capture2e).and_return(['Domain: example.com\nType: unauthorized', failed])

      expect { issuer.issue }
        .to raise_error(PuppetX::Certmanager::Issuer::Base::Error, %r{unauthorized})
    end

    it 'says so plainly when certbot is not installed' do
      allow(Open3).to receive(:capture2e).and_raise(Errno::ENOENT)

      expect { issuer.issue }
        .to raise_error(PuppetX::Certmanager::Issuer::Base::Error, %r{not installed or not on PATH})
    end
  end

  describe '#sync' do
    it 'mirrors certbot output into the canonical store' do
      stage_lineage
      capture_certbot { issuer.issue }

      store = PuppetX::Certmanager::Store.new('www.example.com')
      expect(store.exist?).to be(true)
      expect(store.metadata).to include('issuer' => 'letsencrypt', 'backend' => 'acme')
    end

    it 'fails loudly when certbot claimed success but produced nothing' do
      allow(Open3).to receive(:capture2e).and_return(['', status])

      expect { issuer.issue }
        .to raise_error(PuppetX::Certmanager::Issuer::Base::Error, %r{no certificate appeared})
    end
  end

  describe '#external_renewal?' do
    it 'is true, because the renewal timer belongs to certbot' do
      expect(issuer.external_renewal?).to be(true)
    end
  end
end
