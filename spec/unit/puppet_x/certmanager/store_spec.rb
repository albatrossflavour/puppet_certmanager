# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/certmanager/store'

describe PuppetX::Certmanager::Store, :store do
  subject(:store) { described_class.new('www.example.com') }

  let(:pair) { CertmanagerSpec.certificate(common_name: 'www.example.com', san: ['example.com']) }
  let(:cert) { pair[0].to_pem }
  let(:key) { pair[1].to_pem }

  describe '#deploy' do
    it 'reports a change on first issuance and none on a repeat' do
      expect(store.deploy(cert: cert, key: key, issuer: 'test', backend: 'selfsigned')).to be(true)
      expect(store.deploy(cert: cert, key: key, issuer: 'test', backend: 'selfsigned')).to be(false)
    end

    it 'keeps private material unreadable and public material readable' do
      store.deploy(cert: cert, key: key)

      expect('%o' % (File.stat(store.paths[:privkey]).mode & 0o777)).to eq('600')
      expect('%o' % (File.stat(store.paths[:combined]).mode & 0o777)).to eq('600')
      expect('%o' % (File.stat(store.paths[:fullchain]).mode & 0o777)).to eq('644')
    end

    it 'writes a fullchain containing the leaf and the intermediates' do
      ca_cert, = CertmanagerSpec.ca
      store.deploy(cert: cert, key: key, chain: ca_cert.to_pem)

      fullchain = File.read(store.paths[:fullchain])
      expect(fullchain.scan('BEGIN CERTIFICATE').size).to eq(2)
      expect(fullchain).to start_with(cert.strip)
    end

    # nginx does not want a chain file and Apache used to insist on one.
    # Writing an empty file for a self-signed certificate would hand nginx
    # something it chokes on, so the file is removed instead.
    it 'leaves no chain file at all when there are no intermediates' do
      store.deploy(cert: cert, key: key, chain: '')
      expect(File).not_to exist(store.paths[:chain])
    end

    it 'records the backend and renewal window so the provider can judge it later' do
      store.deploy(cert: cert, key: key, issuer: 'letsencrypt', backend: 'acme', renew_before_days: 45)

      expect(store.metadata).to include(
        'issuer' => 'letsencrypt',
        'backend' => 'acme',
        'renew_before_days' => 45,
      )
    end

    it 'builds a PKCS#12 bundle only when given a password' do
      store.deploy(cert: cert, key: key)
      expect(File).not_to exist(store.paths[:pkcs12])

      store.deploy(cert: cert, key: key, pkcs12_password: 'changeit')
      expect(File).to exist(store.paths[:pkcs12])
      expect { OpenSSL::PKCS12.new(File.binread(store.paths[:pkcs12]), 'changeit') }.not_to raise_error
    end
  end

  describe '#hooks' do
    let(:log) { File.join(ENV.fetch('CERTMANAGER_ROOT'), 'hook.log') }

    def write_hook(name, body)
      dir = File.join(PuppetX::Certmanager::Paths.hook_dir, 'www.example.com')
      FileUtils.mkdir_p(dir)
      path = File.join(dir, name)
      File.write(path, body)
      File.chmod(0o755, path)
      path
    end

    it 'runs on a change and passes the certificate paths in the environment' do
      write_hook('nginx.sh', "#!/bin/sh\necho \"$CERTMANAGER_REASON $CERTMANAGER_FULLCHAIN\" >> #{log}\n")

      store.deploy(cert: cert, key: key)

      expect(File.read(log)).to eq("issued #{store.paths[:fullchain]}\n")
    end

    it 'does not run when nothing changed' do
      store.deploy(cert: cert, key: key)
      write_hook('nginx.sh', "#!/bin/sh\necho ran >> #{log}\n")

      store.deploy(cert: cert, key: key)

      expect(File).not_to exist(log)
    end

    # One service's broken reload script must not stop the others picking up
    # a renewed certificate, and must not fail the run that renewed it.
    it 'keeps going when one hook fails and reports which one' do
      write_hook('a-broken.sh', "#!/bin/sh\nexit 1\n")
      write_hook('b-working.sh', "#!/bin/sh\necho ran >> #{log}\n")

      store.deploy(cert: cert, key: key)

      expect(File.read(log)).to eq("ran\n")
      expect(store.hooks).to eq(['a-broken.sh'])
    end
  end

  describe '#refresh_from' do
    it 'carries the previous metadata forward when a renewal arrives out of band' do
      store.deploy(cert: cert, key: key, issuer: 'letsencrypt', backend: 'acme', renew_before_days: 45)

      renewed, renewed_key = CertmanagerSpec.certificate(common_name: 'www.example.com', san: ['example.com'], days: 89)
      dir = Dir.mktmpdir('lineage')
      File.write(File.join(dir, 'cert.pem'), renewed.to_pem)
      File.write(File.join(dir, 'privkey.pem'), renewed_key.to_pem)

      expect(store.refresh_from(cert: File.join(dir, 'cert.pem'), key: File.join(dir, 'privkey.pem'))).to be(true)
      expect(store.metadata).to include('issuer' => 'letsencrypt', 'backend' => 'acme', 'renew_before_days' => 45)
    ensure
      FileUtils.rm_rf(dir)
    end
  end

  describe '#remove' do
    it 'takes the whole certificate directory with it' do
      store.deploy(cert: cert, key: key)
      store.remove

      expect(store.exist?).to be(false)
    end
  end
end
