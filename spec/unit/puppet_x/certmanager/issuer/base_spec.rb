# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/certmanager/issuer/acme'
require 'puppet_x/certmanager/issuer/selfsigned'

# Drift detection is the whole idempotency story for this module, so it is
# tested through the one backend that can issue without talking to anything.
describe PuppetX::Certmanager::Issuer::Base, :store do
  subject(:issuer) { PuppetX::Certmanager::Issuer::Selfsigned.new('www.example.com', resource, config) }

  let(:resource) do
    {
      common_name: 'www.example.com',
      san: ['example.com'],
      key_type: 'ecdsa-p256',
      renew_before_days: 30,
      issuer: 'internal',
    }
  end
  let(:config) { { 'validity_days' => 90 } }

  describe '#drift' do
    it 'reports an empty store' do
      expect(issuer.drift).to eq(['no certificate in the store'])
    end

    # Also covers the self-signed case: a self-signed certificate from a
    # self-signed issuer is exactly what was asked for, not a placeholder.
    it 'reports nothing once a matching certificate is in place' do
      issuer.issue
      expect(issuer.drift).to be_empty
    end

    it 'reports a certificate inside its renewal window' do
      PuppetX::Certmanager::Issuer::Selfsigned.new('www.example.com', resource, { 'validity_days' => 10 }).issue

      expect(issuer.drift).to include(a_string_matching(%r{expires in \d+ days}))
    end

    it 'reports an added name' do
      issuer.issue
      widened = PuppetX::Certmanager::Issuer::Selfsigned.new(
        'www.example.com', resource.merge(san: ['example.com', 'new.example.com']), config
      )

      expect(widened.drift).to include(a_string_matching(%r{names changed}))
    end

    it 'reports a removed name' do
      issuer.issue
      narrowed = PuppetX::Certmanager::Issuer::Selfsigned.new('www.example.com', resource.merge(san: []), config)

      expect(narrowed.drift).to include(a_string_matching(%r{names changed}))
    end

    it 'ignores the order names are declared in' do
      PuppetX::Certmanager::Issuer::Selfsigned.new(
        'www.example.com', resource.merge(san: ['b.example.com', 'a.example.com']), config
      ).issue

      reordered = PuppetX::Certmanager::Issuer::Selfsigned.new(
        'www.example.com', resource.merge(san: ['a.example.com', 'b.example.com']), config
      )

      expect(reordered.drift).to be_empty
    end

    it 'reports a changed key type' do
      issuer.issue
      stronger = PuppetX::Certmanager::Issuer::Selfsigned.new(
        'www.example.com', resource.merge(key_type: 'ecdsa-p384'), config
      )

      expect(stronger.drift).to include(a_string_matching(%r{key type changed}))
    end

    # The placeholder exists so a service can start. It must not be mistaken
    # for a successfully issued certificate, or nobody ever finds out the
    # real issuance is failing.
    it 'reports a bootstrap placeholder as drift for a real CA' do
      PuppetX::Certmanager::Issuer::Selfsigned.new('www.example.com', resource, config).bootstrap

      acme = PuppetX::Certmanager::Issuer::Acme.new('www.example.com', resource, { 'directory_url' => 'https://example' })
      expect(acme.drift).to include('bootstrap placeholder still in place')
    end
  end

  describe '#external_renewal?' do
    # Only ACME has a client with its own timer. Everything else renews when
    # Puppet says so, and reporting otherwise would make the provider skip
    # work it has to do.
    it 'is false for a backend with no renewal timer of its own' do
      expect(issuer.external_renewal?).to be(false)
    end
  end

  describe '#issue' do
    it 'refuses to be called on the abstract base rather than silently doing nothing' do
      abstract = described_class.new('www.example.com', resource, config)

      expect { abstract.issue }.to raise_error(NotImplementedError, %r{does not implement})
    end
  end

  describe 'the certificate subject' do
    let(:resource) { super().merge(subject: { 'O' => 'Example Ltd', 'C' => 'AU' }) }

    it 'carries the extra components through alongside the common name' do
      issuer.issue

      expect(issuer.store.info['subject']).to include('O=Example Ltd', 'C=AU', 'CN=www.example.com')
    end
  end

  describe 'the signature digest' do
    {
      'sha384' => 'sha384',
      'sha512' => 'sha512',
      nil => 'sha256',
    }.each do |configured, expected|
      it "signs with #{expected} when the issuer asks for #{configured.inspect}" do
        settings = configured ? config.merge('signature_hash' => configured) : config
        PuppetX::Certmanager::Issuer::Selfsigned.new('www.example.com', resource, settings).issue

        expect(PuppetX::Certmanager::Store.new('www.example.com').info['signature_algorithm'])
          .to match(%r{#{expected}}i)
      end
    end
  end

  describe 'key generation' do
    {
      'rsa-2048' => 'rsa-2048',
      'ecdsa-p384' => 'ecdsa-p384',
      'ecdsa-p521' => 'ecdsa-p521',
      'nonsense' => 'ecdsa-p256',
    }.each do |declared, expected|
      it "produces #{expected} for a declared key type of #{declared}" do
        PuppetX::Certmanager::Issuer::Selfsigned.new(
          'www.example.com', resource.merge(key_type: declared), config
        ).issue

        expect(PuppetX::Certmanager::Store.new('www.example.com').info['key_type']).to eq(expected)
      end
    end
  end

  describe '#desired_names' do
    it 'includes the common name without needing it repeated in the SAN list' do
      expect(issuer.desired_names).to eq(['example.com', 'www.example.com'])
    end

    it 'deduplicates a common name that was repeated anyway' do
      duplicated = PuppetX::Certmanager::Issuer::Selfsigned.new(
        'www.example.com', resource.merge(san: ['www.example.com', 'example.com']), config
      )

      expect(duplicated.desired_names).to eq(['example.com', 'www.example.com'])
    end
  end
end
