# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/certmanager/parser'

describe PuppetX::Certmanager::Parser do
  subject(:parser) { described_class }

  let(:tmpdir) { Dir.mktmpdir('certmanager-parser') }

  after(:each) { FileUtils.rm_rf(tmpdir) }

  def write(cert, name: 'cert.pem')
    path = File.join(tmpdir, name)
    File.write(path, cert.to_pem)
    path
  end

  describe '.parse' do
    it 'describes a certificate' do
      cert, = CertmanagerSpec.certificate(common_name: 'www.example.com', san: ['example.com'], days: 45)
      info = parser.parse(write(cert))

      expect(info).to include(
        'san' => ['example.com', 'www.example.com'],
        'days_left' => 45,
        'expired' => false,
        'self_signed' => true,
        'key_type' => 'ecdsa-p256',
      )
    end

    it 'sorts the SAN list so ordering is never mistaken for drift' do
      cert, = CertmanagerSpec.certificate(common_name: 'zeta.example.com', san: ['alpha.example.com', 'mu.example.com'])

      expect(parser.parse(write(cert))['san'])
        .to eq(['alpha.example.com', 'mu.example.com', 'zeta.example.com'])
    end

    it 'reads the leaf out of a full chain rather than the intermediate' do
      ca_cert, ca_key = CertmanagerSpec.ca
      leaf, = CertmanagerSpec.certificate(common_name: 'leaf.example.com', issuer: ca_cert, issuer_key: ca_key)

      path = File.join(tmpdir, 'fullchain.pem')
      File.write(path, leaf.to_pem + ca_cert.to_pem)

      expect(parser.parse(path)).to include(
        'subject' => 'CN=leaf.example.com',
        'self_signed' => false,
      )
    end

    it 'reports a negative day count for an expired certificate' do
      cert, = CertmanagerSpec.certificate(days: -10)
      info = parser.parse(write(cert))

      expect(info['expired']).to be(true)
      expect(info['days_left']).to be < 0
    end

    # The scan runs across whatever happens to be in /etc/pki. One private
    # key or one truncated file must not take the whole fact down.
    it 'returns nil for a file that is not a certificate' do
      path = File.join(tmpdir, 'notacert.pem')
      File.write(path, "-----BEGIN RSA PRIVATE KEY-----\nrubbish\n-----END RSA PRIVATE KEY-----\n")

      expect(parser.parse(path)).to be_nil
    end

    it 'returns nil for a file it cannot read' do
      expect(parser.parse(File.join(tmpdir, 'nothing-here.pem'))).to be_nil
    end
  end

  describe '.key_type' do
    it 'names an RSA key by its size' do
      cert, = CertmanagerSpec.certificate(key_type: 'rsa-2048')
      expect(parser.key_type(cert)).to eq('rsa-2048')
    end

    it 'names an EC key by its curve, using the same vocabulary as the manifest' do
      cert, = CertmanagerSpec.certificate(key_type: 'ecdsa-p384')
      expect(parser.key_type(cert)).to eq('ecdsa-p384')
    end

    it 'names a DSA key rather than reporting it as unknown' do
      skip 'OpenSSL 3 refuses to generate DSA keys in the default provider' unless dsa_available?

      cert = OpenSSL::X509::Certificate.new
      cert.public_key = OpenSSL::PKey::DSA.new(2048).public_key

      expect(parser.key_type(cert)).to match(%r{\Adsa-\d+\z})
    end

    # The scan runs over whatever is on disk. Something it cannot identify
    # must come back as unknown rather than taking the fact down.
    it 'says unknown rather than raising when the key cannot be read' do
      cert = instance_double(OpenSSL::X509::Certificate)
      allow(cert).to receive(:public_key).and_raise(OpenSSL::PKey::PKeyError)

      expect(parser.key_type(cert)).to eq('unknown')
    end

    def dsa_available?
      OpenSSL::PKey::DSA.new(2048)
      true
    rescue StandardError
      false
    end
  end

  describe '.self_signed?' do
    # A cross-signed intermediate has the same subject and issuer without
    # being self-signed, so comparing the two names is not enough.
    it 'verifies the signature rather than comparing names' do
      ca_cert, ca_key = CertmanagerSpec.ca(common_name: 'Same Name')
      impostor, = CertmanagerSpec.certificate(common_name: 'Same Name', issuer: ca_cert, issuer_key: ca_key)

      expect(parser.self_signed?(impostor)).to be(false)
    end

    it 'says no rather than raising when the signature cannot be checked' do
      cert = instance_double(OpenSSL::X509::Certificate)
      allow(cert).to receive_messages(subject: 'a', issuer: 'a', public_key: nil)
      allow(cert).to receive(:verify).and_raise(OpenSSL::PKey::PKeyError)

      expect(parser.self_signed?(cert)).to be(false)
    end
  end

  describe '.days_between' do
    it 'floors rather than rounds, so a certificate is never reported as lasting longer than it does' do
      now = Time.utc(2026, 1, 1, 0, 0, 0)
      expect(parser.days_between(now, now + (86_400 * 3) + 82_800)).to eq(3)
    end
  end
end
