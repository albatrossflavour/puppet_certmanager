# frozen_string_literal: true

require 'spec_helper'

describe 'certmanager::path' do
  let(:facts) { { os: { 'family' => 'RedHat', 'name' => 'RedHat', 'release' => { 'major' => '9' } }, kernel: 'Linux' } }

  it { is_expected.to run.with_params('www.example.com').and_return('/etc/certmanager/certs/www.example.com/fullchain.pem') }

  # The whole reason this function exists: an nginx template calling it
  # keeps working when the certificate moves from Let's Encrypt to DigiCert,
  # because the store layout does not change with the issuer.
  it 'returns the same path whichever CA signed the certificate' do
    expect(subject).to run.with_params('www.example.com', 'privkey')
                          .and_return('/etc/certmanager/certs/www.example.com/privkey.pem')
  end

  ['cert', 'chain', 'fullchain', 'privkey', 'combined', 'pkcs12', 'metadata'].each do |component|
    it "resolves the #{component} component" do
      expect(subject).to run.with_params('www.example.com', component)
                            .and_return(%r{\A/etc/certmanager/certs/www\.example\.com/})
    end
  end

  it 'returns the directory itself when asked' do
    expect(subject).to run.with_params('www.example.com', 'dir')
                          .and_return('/etc/certmanager/certs/www.example.com')
  end

  it 'rejects a component it does not know about' do
    expect(subject).to run.with_params('www.example.com', 'nonsense').and_raise_error(ArgumentError)
  end

  it 'rejects a name that would escape the store' do
    expect(subject).to run.with_params('../../etc/shadow').and_raise_error(ArgumentError)
  end

  context 'with Windows facts' do
    let(:facts) { { os: { 'family' => 'windows', 'name' => 'windows', 'release' => { 'major' => '2022' } }, kernel: 'windows' } }

    it 'uses the Windows store location' do
      expect(subject).to run.with_params('www.example.com')
                            .and_return('C:/ProgramData/PuppetLabs/certmanager/certs/www.example.com/fullchain.pem')
    end
  end
end
