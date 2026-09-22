# frozen_string_literal: true

require 'spec_helper'
require 'puppet/resource_api'

ensure_module_defined('Puppet::Provider::CertmanagerCertificate')
require 'puppet/provider/certmanager_certificate/certmanager_certificate'
require 'puppet_x/certmanager/store'

describe Puppet::Provider::CertmanagerCertificate::CertmanagerCertificate, :store do
  subject(:provider) { described_class.new }

  let(:context) { instance_double(Puppet::ResourceApi::BaseContext, 'context') }
  let(:test_ca) { CertmanagerSpec.ca }

  let(:selfsigned) do
    {
      name: 'www.example.com',
      ensure: 'present',
      issuer: 'internal',
      issuer_config: { 'backend' => 'selfsigned', 'validity_days' => 90 },
      common_name: 'www.example.com',
      # As certmanager::certificate builds it: every name on the finished
      # certificate, common name included.
      san: ['example.com', 'www.example.com'],
      key_type: 'ecdsa-p256',
      renew_before_days: 30,
      certificate_state: 'current',
      subject: {},
    }
  end

  before(:each) do
    allow(context).to receive(:notice)
    allow(context).to receive(:warning)
    allow(context).to receive(:creating).and_yield
    allow(context).to receive(:updating).and_yield
    allow(context).to receive(:deleting).and_yield
  end

  # CA-signed by default. A self-signed certificate recorded against a real
  # CA backend is, correctly, reported as a leftover bootstrap placeholder,
  # so signing these properly is the difference between testing the code and
  # testing the fixture.
  def deploy(name: 'www.example.com', days: 90, backend: 'acme', issuer: 'letsencrypt',
             renew_before_days: 30, san: [], self_signed: false)
    cert, key = if self_signed
                  CertmanagerSpec.certificate(common_name: name, san: san, days: days)
                else
                  CertmanagerSpec.certificate(common_name: name, san: san, days: days,
                                              issuer: test_ca[0], issuer_key: test_ca[1])
                end

    PuppetX::Certmanager::Store.new(name).deploy(
      cert: cert.to_pem, key: key.to_pem, chain: test_ca[0].to_pem,
      issuer: issuer, backend: backend, renew_before_days: renew_before_days
    )
  end

  describe '#get' do
    it 'reports absent for a certificate that is not there' do
      expect(provider.get(context, ['www.example.com']).first)
        .to include(name: 'www.example.com', ensure: 'absent', certificate_state: 'missing')
    end

    it 'reads the certificate out of the store' do
      deploy(san: ['example.com'], days: 90)

      expect(provider.get(context, ['www.example.com']).first).to include(
        ensure: 'present',
        certificate_state: 'current',
        san: ['example.com', 'www.example.com'],
        key_type: 'ecdsa-p256',
        days_left: 90,
      )
    end

    # This is what makes time-based renewal work at all: an expiring
    # certificate has to show up as drift in the report, not stay quietly
    # "present" until the morning it breaks.
    it 'reports a certificate inside its renewal window as drift' do
      deploy(days: 10, renew_before_days: 30)

      expect(provider.get(context, ['www.example.com']).first[:certificate_state]).to eq('renewal_due')
    end

    it 'honours the renewal window the certificate was deployed with' do
      deploy(days: 40, renew_before_days: 60)

      expect(provider.get(context, ['www.example.com']).first[:certificate_state]).to eq('renewal_due')
    end

    it 'reports a bootstrap placeholder as a placeholder, not as a working certificate' do
      deploy(backend: 'placeholder', self_signed: true)

      expect(provider.get(context, ['www.example.com']).first[:certificate_state]).to eq('placeholder')
    end

    it 'discovers everything in the store when asked for no name in particular' do
      deploy(name: 'a.example.com')
      deploy(name: 'b.example.com')

      expect(provider.get(context).map { |r| r[:name] }).to contain_exactly('a.example.com', 'b.example.com')
    end

    it 'flags an unreadable certificate rather than reporting it absent' do
      deploy
      File.write(PuppetX::Certmanager::Store.new('www.example.com').paths[:cert], 'not a certificate')

      expect(provider.get(context, ['www.example.com']).first)
        .to include(ensure: 'present', certificate_state: 'unreadable')
    end
  end

  describe '#canonicalize' do
    # Without this, a manifest listing names in a different order from the
    # certificate reports drift on every single run.
    it 'sorts and deduplicates the declared names' do
      result = provider.canonicalize(context, [{ name: 'x', san: ['b.example.com', 'a.example.com', 'b.example.com'] }])

      expect(result.first[:san]).to eq(['a.example.com', 'b.example.com'])
    end
  end

  describe '#set' do
    it 'issues a certificate that does not exist yet' do
      provider.set(context, 'www.example.com' => { is: { name: 'www.example.com', ensure: 'absent' }, should: selfsigned })

      expect(PuppetX::Certmanager::Store.new('www.example.com').exist?).to be(true)
    end

    it 'renews one that has drifted, and says why' do
      deploy(days: 5, backend: 'selfsigned', issuer: 'internal', san: ['example.com'], self_signed: true)
      current = provider.get(context, ['www.example.com']).first

      expect(context).to receive(:notice).with(%r{Renewing certificate www\.example\.com: expires in \d+ days})

      provider.set(context, 'www.example.com' => { is: current, should: selfsigned })

      expect(PuppetX::Certmanager::Store.new('www.example.com').info['days_left']).to be >= 89
    end

    # The test that would have caught the SAN mismatch: issue, then read
    # back, and confirm nothing the resource declares still looks different.
    # A unit test that only checks "a certificate appeared" will happily pass
    # while the real thing reissues on every run.
    it 'leaves nothing to do on a second run' do
      provider.set(context, 'www.example.com' => { is: { name: 'www.example.com', ensure: 'absent' }, should: selfsigned })

      current = provider.get(context, ['www.example.com']).first
      should = provider.canonicalize(context, [selfsigned.dup]).first

      expect(current[:san]).to eq(should[:san])
      expect(current[:key_type]).to eq(should[:key_type])
      expect(current[:certificate_state]).to eq(should[:certificate_state])
      expect(current[:ensure]).to eq(should[:ensure])
    end

    it 'rebuilds the fact cache so the next run does not report stale expiry data' do
      provider.set(context, 'www.example.com' => { is: { name: 'www.example.com', ensure: 'absent' }, should: selfsigned })

      cache = JSON.parse(File.read(PuppetX::Certmanager::Paths.cache_file))
      expect(cache['certificates']).to have_key('www.example.com')
    end

    # Removing a certificate from a manifest is usually a refactor, and the
    # key is not recoverable.
    it 'leaves the files alone on absent unless purging was asked for' do
      deploy(backend: 'selfsigned', issuer: 'internal', self_signed: true)

      expect(context).to receive(:notice).with(%r{files left in the store})

      provider.set(context, 'www.example.com' => {
                     is: { name: 'www.example.com', ensure: 'present' },
                     should: selfsigned.merge(ensure: 'absent'),
                   })

      expect(PuppetX::Certmanager::Store.new('www.example.com').exist?).to be(true)
    end

    it 'deletes the files when purging was asked for' do
      deploy(backend: 'selfsigned', issuer: 'internal', self_signed: true)

      provider.set(context, 'www.example.com' => {
                     is: { name: 'www.example.com', ensure: 'present' },
                     should: selfsigned.merge(ensure: 'absent', purge_on_absent: true),
                   })

      expect(PuppetX::Certmanager::Store.new('www.example.com').exist?).to be(false)
    end

    it 'does nothing at all when the certificate is absent and should stay that way' do
      expect(context).not_to receive(:deleting)

      provider.set(context, 'www.example.com' => {
                     is: { name: 'www.example.com', ensure: 'absent' },
                     should: selfsigned.merge(ensure: 'absent'),
                   })
    end

    it 'turns a backend failure into a Puppet error rather than a stack trace' do
      allow(context).to receive(:err)
      broken = selfsigned.merge(issuer_config: { 'backend' => 'nonesuch' })

      expect {
        provider.set(context, 'www.example.com' => { is: { name: 'www.example.com', ensure: 'absent' }, should: broken })
      }.to raise_error(Puppet::Error, %r{unknown issuer backend})
    end
  end
end
