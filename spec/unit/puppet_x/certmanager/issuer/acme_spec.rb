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
      # args.first is the environment hash the backend always passes.
      captured = args.drop(1)
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

    # certbot takes several settings from the environment and offers no
    # flag for them, so an issuer behind a proxy or pointed at a privately
    # signed ACME endpoint has nowhere else to put them.
    context 'with environment settings' do
      let(:config) { super().merge('environment' => { 'HTTPS_PROXY' => 'http://proxy:3128' }) }

      it 'hands them to the client' do
        stage_lineage
        captured = nil
        allow(Open3).to receive(:capture2e) do |*args, **_kwargs|
          captured = args.first
          ['', status]
        end

        issuer.issue

        expect(captured).to eq('HTTPS_PROXY' => 'http://proxy:3128')
      end
    end

    it 'passes an empty environment when the issuer sets none' do
      stage_lineage
      captured = nil
      allow(Open3).to receive(:capture2e) do |*args, **_kwargs|
        captured = args.first
        ['', status]
      end

      issuer.issue

      expect(captured).to eq({})
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

  describe 'with external account binding' do
    let(:config) { super().merge('eab_kid' => 'kid-1', 'eab_hmac_key' => 'hmac-secret') }

    # ZeroSSL, Buypass and DigiCert's own ACME service all require this, and
    # certbot silently registers a useless account without it.
    it 'registers the account against the binding' do
      stage_lineage
      args = capture_certbot { issuer.issue }

      expect(args).to include('--eab-kid', 'kid-1', '--eab-hmac-key', 'hmac-secret')
    end
  end

  describe 'challenge selection' do
    context 'with tls-alpn-01' do
      let(:config) { super().merge('challenge' => 'tls-alpn-01') }

      it 'stands up its own listener, because there is no webroot equivalent' do
        stage_lineage
        args = capture_certbot { issuer.issue }

        expect(args).to include('--standalone', '--preferred-challenges', 'tls-alpn-01')
      end
    end

    context 'with a stronger curve' do
      let(:resource) { super().merge(key_type: 'ecdsa-p384') }

      it 'names the curve certbot expects' do
        stage_lineage
        args = capture_certbot { issuer.issue }

        expect(args).to include('--elliptic-curve', 'secp384r1')
      end
    end
  end

  describe '#revoke' do
    it 'tells the CA, with the reason it was given' do
      stage_lineage
      capture_certbot { issuer.issue }

      args = capture_certbot do
        described_class.new('www.example.com', resource.merge(revocation_reason: 'keycompromise'), config).revoke
      end

      expect(args).to include('revoke', '--reason', 'keycompromise')
    end

    # win-acme has no equivalent subcommand, and shelling out to certbot on a
    # host that has never had it is a confusing way to fail.
    it 'does nothing on Windows' do
      allow(PuppetX::Certmanager::Paths).to receive(:windows?).and_return(true)

      expect(Open3).not_to receive(:capture2e)
      issuer.revoke
    end
  end

  describe 'on Windows' do
    before(:each) { allow(PuppetX::Certmanager::Paths).to receive(:windows?).and_return(true) }

    let(:wacs_dir) { File.join(PuppetX::Certmanager::Paths.state_dir, 'win-acme', 'www.example.com') }

    def stage_wacs(days: 90)
      FileUtils.mkdir_p(wacs_dir)
      ca_cert, ca_key = CertmanagerSpec.ca
      cert, key = CertmanagerSpec.certificate(common_name: 'www.example.com', san: ['example.com'],
                                              days: days, issuer: ca_cert, issuer_key: ca_key)
      File.write(File.join(wacs_dir, 'www.example.com-crt.pem'), cert.to_pem)
      File.write(File.join(wacs_dir, 'www.example.com-key.pem'), key.to_pem)
      File.write(File.join(wacs_dir, 'www.example.com-chain-only.pem'), ca_cert.to_pem)
    end

    it 'drives win-acme rather than certbot' do
      stage_wacs
      args = capture_certbot { issuer.issue }

      expect(args.first).to eq('wacs.exe')
      expect(args).to include('--source', 'manual', '--host', 'example.com,www.example.com')
    end

    it 'honours the configured wacs path' do
      stage_wacs
      configured = described_class.new('www.example.com', resource,
                                       config.merge('wacs_path' => 'C:/tools/wacs.exe'))
      args = capture_certbot { configured.issue }

      expect(args.first).to eq('C:/tools/wacs.exe')
    end

    it 'passes the account binding across under win-acme own flag names' do
      stage_wacs
      bound = described_class.new('www.example.com', resource,
                                  config.merge('eab_kid' => 'kid-1', 'eab_hmac_key' => 'hmac-secret'))
      args = capture_certbot { bound.issue }

      expect(args).to include('--eab-key-identifier', 'kid-1', '--eab-key', 'hmac-secret')
    end

    it 'self-hosts validation when no webroot is given' do
      stage_wacs
      args = capture_certbot { issuer.issue }

      expect(args).to include('--validation', 'selfhosting')
    end

    it 'serves the challenge from the webroot when there is one' do
      stage_wacs
      served = described_class.new('www.example.com', resource, config.merge('webroot' => 'C:/inetpub/wwwroot'))
      args = capture_certbot { served.issue }

      expect(args).to include('--validation', 'filesystem', '--webroot', 'C:/inetpub/wwwroot')
    end

    it 'mirrors win-acme output into the same canonical store' do
      stage_wacs
      capture_certbot { issuer.issue }

      expect(PuppetX::Certmanager::Store.new('www.example.com').exist?).to be(true)
    end
  end

  describe 'DNS credentials' do
    let(:config) { super().merge('challenge' => 'dns-01', 'dns_plugin' => 'cloudflare', 'dns_credentials' => 'token') }

    # certbot refuses a credentials file anyone else can read, so the
    # manifest writes it at 0600 and the backend only has to agree on where.
    it 'points the plugin at the file the manifest writes, named for the issuer' do
      stage_lineage
      args = capture_certbot { issuer.issue }

      expect(args).to include('--dns-cloudflare-credentials',
                              File.join(PuppetX::Certmanager::Paths.credential_dir, 'letsencrypt.ini'))
    end
  end

  describe '#external_renewal?' do
    it 'is true, because the renewal timer belongs to certbot' do
      expect(issuer.external_renewal?).to be(true)
    end
  end
end
