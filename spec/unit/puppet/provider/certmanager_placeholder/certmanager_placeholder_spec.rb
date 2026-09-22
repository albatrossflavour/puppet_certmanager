# frozen_string_literal: true

require 'spec_helper'
require 'puppet/resource_api'

ensure_module_defined('Puppet::Provider::CertmanagerPlaceholder')
require 'puppet/provider/certmanager_placeholder/certmanager_placeholder'
require 'puppet_x/certmanager/store'

describe Puppet::Provider::CertmanagerPlaceholder::CertmanagerPlaceholder, :store do
  subject(:provider) { described_class.new }

  let(:context) { instance_double(Puppet::ResourceApi::BaseContext, 'context') }
  let(:store) { PuppetX::Certmanager::Store.new('www.example.com') }

  let(:should_hash) do
    {
      name: 'www.example.com',
      ensure: 'present',
      common_name: 'www.example.com',
      san: ['example.com'],
      key_type: 'ecdsa-p256',
      validity_days: 30,
      subject: {},
    }
  end

  before(:each) do
    allow(context).to receive(:notice)
    allow(context).to receive(:creating).and_yield
    allow(context).to receive(:deleting).and_yield
  end

  def apply(should)
    provider.set(context, 'www.example.com' => { is: provider.get(context, ['www.example.com']).first, should: should })
  end

  describe '#set' do
    it 'writes a placeholder when the store is empty' do
      apply(should_hash)

      expect(store.exist?).to be(true)
      expect(store.metadata['backend']).to eq('placeholder')
    end

    it 'puts the declared names on it so SNI matching still works' do
      apply(should_hash)

      expect(store.info['san']).to eq(['example.com', 'www.example.com'])
    end

    it 'is short-lived on purpose, so one left in place sets off an alert' do
      apply(should_hash)

      expect(store.info['days_left']).to be <= 30
    end

    # Replacing a valid public certificate with a self-signed one as a side
    # effect of a Puppet run would be considerably worse than the deadlock
    # this resource exists to break.
    it 'never overwrites a certificate that is already there' do
      cert, key = CertmanagerSpec.certificate(common_name: 'www.example.com', days: 90)
      store.deploy(cert: cert.to_pem, key: key.to_pem, issuer: 'letsencrypt', backend: 'acme')
      before = store.fingerprint

      apply(should_hash)

      expect(store.fingerprint).to eq(before)
      expect(store.metadata['backend']).to eq('acme')
    end

    it 'does nothing on a second run' do
      apply(should_hash)
      before = store.fingerprint

      apply(should_hash)

      expect(store.fingerprint).to eq(before)
    end
  end

  describe 'removal' do
    it 'removes a placeholder that is still a placeholder' do
      apply(should_hash)
      apply(should_hash.merge(ensure: 'absent'))

      expect(store.exist?).to be(false)
    end

    # By the time anyone removes the bootstrap resource, the store may well
    # hold the real certificate it existed to make way for.
    it 'refuses to remove the real certificate that replaced one' do
      cert, key = CertmanagerSpec.certificate(common_name: 'www.example.com', days: 90)
      store.deploy(cert: cert.to_pem, key: key.to_pem, issuer: 'letsencrypt', backend: 'acme')

      expect(context).to receive(:notice).with(%r{a real certificate has replaced the placeholder})

      apply(should_hash.merge(ensure: 'absent'))

      expect(store.exist?).to be(true)
    end
  end
end
