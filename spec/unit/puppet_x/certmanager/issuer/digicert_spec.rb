# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/certmanager/issuer/digicert'

describe PuppetX::Certmanager::Issuer::Digicert, :store do
  subject(:issuer) { described_class.new('payments.example.com', resource, config) }

  let(:resource) do
    { common_name: 'payments.example.com', san: [], key_type: 'rsa-2048', issuer: 'digicert' }
  end
  let(:config) { { 'api_key' => 'secret', 'organization_id' => 42 } }

  let(:pair) { CertmanagerSpec.certificate(common_name: 'payments.example.com', key_type: 'rsa-2048') }
  let(:ca_pair) { CertmanagerSpec.ca }

  def response(code, body)
    klass = (code == 200) ? Net::HTTPOK : Net::HTTPBadRequest
    instance_double(klass, code: code.to_s, body: body).tap do |double|
      allow(double).to receive(:is_a?).with(Net::HTTPSuccess).and_return(code == 200)
    end
  end

  def stub_http(*responses)
    allow(Net::HTTP).to receive(:start).and_return(*responses)
  end

  # Net::HTTP.start yields the connection and the backend builds its request
  # inside that block, so this is the only place the outbound body can be
  # seen without reaching into the object under test.
  def capture_request(block)
    captured = nil
    http = instance_double(Net::HTTP)
    allow(http).to receive(:request) { |req| captured = req }
    block.call(http)
    captured
  end

  describe '#issue' do
    it 'places an order, waits for issuance, and lands the chain in the store' do
      bundle = pair[0].to_pem + ca_pair[0].to_pem

      stub_http(
        response(200, JSON.generate('id' => 9001)),
        response(200, JSON.generate('status' => 'issued', 'certificate' => { 'id' => 77 })),
        response(200, bundle),
      )

      issuer.issue

      store = PuppetX::Certmanager::Store.new('payments.example.com')
      expect(store.exist?).to be(true)
      expect(store.metadata).to include('backend' => 'digicert', 'issuer' => 'digicert')
      expect(File.read(store.paths[:chain])).to include('BEGIN CERTIFICATE')
    end

    # Orders cost money. Placing a second one because Puppet ran again
    # before DigiCert finished validating the first is a billing incident,
    # not a retry.
    it 'refuses to place a second order while the first is still pending' do
      stub_http(
        response(200, JSON.generate('id' => 9001)),
        response(200, JSON.generate('status' => 'pending')),
      )

      begin
        issuer.issue
      rescue PuppetX::Certmanager::Issuer::Base::Error
        nil
      end

      stub_http(response(200, JSON.generate('status' => 'pending')))

      expect { issuer.issue }
        .to raise_error(PuppetX::Certmanager::Issuer::Base::Error, %r{still pending validation})
    end

    it 'sends a CSR and never the private key' do
      sent = nil
      allow(Net::HTTP).to receive(:start) do |*_args, &block|
        request = block ? capture_request(block) : nil
        sent ||= request&.body
        response(200, JSON.generate('id' => 9001, 'status' => 'pending'))
      end

      begin
        issuer.issue
      rescue PuppetX::Certmanager::Issuer::Base::Error
        nil
      end

      expect(sent).to include('BEGIN CERTIFICATE REQUEST')
      expect(sent).not_to include('PRIVATE KEY')
    end

    it 'keeps the private key on the host, readable only by root' do
      stub_http(
        response(200, JSON.generate('id' => 9001)),
        response(200, JSON.generate('status' => 'pending')),
      )

      begin
        issuer.issue
      rescue PuppetX::Certmanager::Issuer::Base::Error
        nil
      end

      key_file = File.join(PuppetX::Certmanager::Paths.state_dir, 'digicert', 'payments.example.com.key')
      expect(File).to exist(key_file)
      expect('%o' % (File.stat(key_file).mode & 0o777)).to eq('600')
    end

    it 'surfaces the CertCentral error message rather than just the status code' do
      stub_http(response(400, JSON.generate('errors' => [{ 'message' => 'organization not validated' }])))

      expect { issuer.issue }
        .to raise_error(PuppetX::Certmanager::Issuer::Base::Error, %r{organization not validated})
    end

    it 'surfaces a non-JSON error body rather than swallowing it' do
      stub_http(response(400, '<html>502 Bad Gateway</html>'))

      expect { issuer.issue }
        .to raise_error(PuppetX::Certmanager::Issuer::Base::Error, %r{502 Bad Gateway})
    end

    it 'says so plainly when CertCentral cannot be reached' do
      allow(Net::HTTP).to receive(:start).and_raise(SocketError, 'getaddrinfo failed')

      expect { issuer.issue }
        .to raise_error(PuppetX::Certmanager::Issuer::Base::Error, %r{could not reach DigiCert})
    end
  end

  describe '#revoke' do
    # Revocation is not the same as forgetting. The order record is what
    # tells us which certificate to revoke, so it goes only once the CA has
    # accepted it.
    it 'revokes the issued certificate and then forgets the order' do
      bundle = pair[0].to_pem + ca_pair[0].to_pem
      stub_http(
        response(200, JSON.generate('id' => 9001)),
        response(200, JSON.generate('status' => 'issued', 'certificate' => { 'id' => 77 })),
        response(200, bundle),
      )
      issuer.issue

      order_file = File.join(PuppetX::Certmanager::Paths.state_dir, 'digicert', 'payments.example.com.json')
      expect(File).to exist(order_file)

      stub_http(
        response(200, JSON.generate('status' => 'issued', 'certificate' => { 'id' => 77 })),
        response(200, '{}'),
      )
      issuer.revoke

      expect(File).not_to exist(order_file)
    end

    it 'does nothing when there is no order to revoke' do
      expect(Net::HTTP).not_to receive(:start)
      issuer.revoke
    end

    it 'does nothing when the order never produced a certificate' do
      stub_http(
        response(200, JSON.generate('id' => 9001)),
        response(200, JSON.generate('status' => 'pending')),
      )
      begin
        issuer.issue
      rescue PuppetX::Certmanager::Issuer::Base::Error
        nil
      end

      stub_http(response(200, JSON.generate('status' => 'pending')))
      expect { issuer.revoke }.not_to raise_error
    end
  end
end
