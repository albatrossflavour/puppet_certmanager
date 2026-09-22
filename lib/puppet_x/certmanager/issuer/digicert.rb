# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'net/http'
require 'uri'

require_relative 'base'

module PuppetX
  module Certmanager
    module Issuer
      # DigiCert CertCentral.
      #
      # Nothing like ACME. Orders are placed against a REST API, they cost
      # money, and depending on the product and the organisation's validation
      # state an order can sit pending for days waiting on a human at
      # DigiCert. Three consequences shape this backend:
      #
      # 1. Order state is persisted locally. Placing a duplicate order
      #    because Puppet ran again before the first one completed is a
      #    billing incident, not a retry.
      # 2. A pending order is a normal state, not a failure. The provider
      #    reports it and moves on.
      # 3. The private key never leaves the host. Puppet generates it and
      #    sends only a CSR.
      class Digicert < Base
        DEFAULT_API = 'https://www.digicert.com/services/v2'
        DEFAULT_PRODUCT = 'ssl_securesite_flex'

        # Order states CertCentral reports while the order is still being
        # worked. Anything else is either done or wants a human.
        PENDING_STATES = ['pending', 'processing', 'reissue_pending', 'waiting_pickup', 'needs_approval', 'needs_csr'].freeze

        # @return [void]
        def issue
          order = load_order

          if order && PENDING_STATES.include?(order_status(order['order_id']))
            raise Error, "certmanager: DigiCert order #{order['order_id']} for #{name} is still pending " \
                         'validation; nothing to do until DigiCert issues it'
          end

          order = place_order if order.nil? || certificate_id(order['order_id']).nil?
          download_and_deploy(order)
        end

        # @return [void]
        def revoke
          order = load_order
          return if order.nil?

          cert_id = certificate_id(order['order_id'])
          return if cert_id.nil?

          request(:put, "/certificate/#{cert_id}/revoke",
                  'comments' => resource[:revocation_reason] || 'Revoked by certmanager')
          FileUtils.rm_f(order_file)
        end

        private

        # Place a fresh order, persisting the private key and the order
        # record before the API call returns anything, so a crash between
        # the order and the response doesn't orphan a paid certificate.
        #
        # @return [Hash]
        def place_order
          key = generate_key
          csr = build_csr(key)

          FileUtils.mkdir_p(File.dirname(order_file), mode: 0o700)
          File.write(key_file, key.to_pem)
          File.chmod(0o600, key_file)

          product = config['product_name_id'] || DEFAULT_PRODUCT
          body = {
            'certificate' => {
              'common_name' => resource[:common_name] || name,
              'dns_names' => desired_names,
              'csr' => csr.to_pem,
              'signature_hash' => config['signature_hash'] || 'sha256',
            },
            'organization' => { 'id' => config['organization_id'] },
            'validity_years' => config['validity_years'] || 1,
          }
          body['container'] = { 'id' => config['container_id'] } if config['container_id']

          response = request(:post, "/order/certificate/#{product}", body)

          order = {
            'order_id' => response['id'],
            'placed_at' => Time.now.utc.iso8601,
            'names' => desired_names,
            'product' => product,
          }
          File.write(order_file, JSON.pretty_generate(order))
          File.chmod(0o600, order_file)
          order
        end

        # @param order [Hash]
        # @return [void]
        def download_and_deploy(order)
          cert_id = certificate_id(order['order_id'])
          raise Error, "certmanager: DigiCert order #{order['order_id']} has no issued certificate yet" if cert_id.nil?

          bundle = request(:get, "/certificate/#{cert_id}/download/format/pem_all", nil, raw: true)
          certs = bundle.scan(%r{-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----}m)
          raise Error, "certmanager: DigiCert returned no certificates for #{name}" if certs.empty?

          store.deploy(
            cert: certs.first,
            chain: certs.drop(1).join("\n"),
            key: File.read(key_file),
            **store_metadata,
          )
        end

        # @param order_id [Integer]
        # @return [String, nil]
        def order_status(order_id)
          request(:get, "/order/certificate/#{order_id}")['status']
        end

        # @param order_id [Integer]
        # @return [Integer, nil]
        def certificate_id(order_id)
          response = request(:get, "/order/certificate/#{order_id}")
          return nil unless response['status'] == 'issued'

          response.dig('certificate', 'id')
        end

        # @return [Hash, nil]
        def load_order
          JSON.parse(File.read(order_file))
        rescue SystemCallError, IOError, JSON::ParserError
          nil
        end

        # @return [String]
        def order_file
          File.join(Paths.state_dir, 'digicert', "#{name}.json")
        end

        # @return [String]
        def key_file
          File.join(Paths.state_dir, 'digicert', "#{name}.key")
        end

        # @param method [Symbol]
        # @param path [String]
        # @param body [Hash, nil]
        # @param raw [Boolean] return the response body unparsed
        # @return [Hash, String]
        def request(method, path, body = nil, raw: false)
          uri = URI.parse((config['api_url'] || DEFAULT_API) + path)

          klass = { get: Net::HTTP::Get, post: Net::HTTP::Post, put: Net::HTTP::Put }.fetch(method)
          req = klass.new(uri)
          req['X-DC-DEVKEY'] = secret(config['api_key'])
          req['Content-Type'] = 'application/json'
          req['Accept'] = raw ? 'text/plain' : 'application/json'
          req.body = JSON.generate(body) if body

          response = Net::HTTP.start(uri.hostname, uri.port,
                                     use_ssl: uri.scheme == 'https',
                                     open_timeout: 15, read_timeout: 120) do |http|
            http.request(req)
          end

          handle(response, raw: raw)
        rescue SocketError, Net::OpenTimeout, Net::ReadTimeout => e
          raise Error, "certmanager: could not reach DigiCert CertCentral: #{e.message}"
        end

        # @return [Hash, String]
        def handle(response, raw:)
          unless response.is_a?(Net::HTTPSuccess)
            detail = begin
              JSON.parse(response.body).fetch('errors', []).map { |e| e['message'] }.join('; ')
            rescue JSON::ParserError
              response.body.to_s[0, 200]
            end
            raise Error, "certmanager: DigiCert returned #{response.code} for #{name}: #{detail}"
          end

          return response.body if raw
          return {} if response.body.to_s.strip.empty?

          JSON.parse(response.body)
        end
      end
    end
  end
end
