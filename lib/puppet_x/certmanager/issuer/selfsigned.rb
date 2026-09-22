# frozen_string_literal: true

require 'securerandom'

require_relative 'base'

module PuppetX
  module Certmanager
    module Issuer
      # Self-signed certificates.
      #
      # Two jobs. The obvious one is internal services and labs where a real
      # CA is overkill. The less obvious one matters more: this backend
      # produces the bootstrap placeholder that lets nginx start before a
      # real certificate exists, which is what breaks the first-run deadlock
      # where the web server won't start without a certificate and the
      # http-01 challenge can't succeed without the web server.
      class Selfsigned < Base
        # @return [void]
        def issue
          key = generate_key
          cert = build_certificate(key)

          store.deploy(cert: cert.to_pem, key: key.to_pem, **store_metadata)
        end

        # Recorded against a placeholder so the fact can tell it apart from
        # a certificate that is self-signed because somebody meant it to be.
        #
        # @return [String]
        def backend
          @placeholder ? 'placeholder' : 'selfsigned'
        end

        # Write a placeholder without disturbing an existing certificate.
        #
        # Called by the bootstrap path, which must never overwrite a real
        # certificate: getting that wrong would replace a valid public
        # certificate with a self-signed one on every run.
        #
        # @return [Boolean] true when a placeholder was written
        def bootstrap
          return false if store.exist?

          @placeholder = true
          issue
          true
        end

        private

        # @param key [OpenSSL::PKey::PKey]
        # @return [OpenSSL::X509::Certificate]
        def build_certificate(key)
          now = Time.now
          cert = OpenSSL::X509::Certificate.new
          cert.version = 2
          cert.serial = OpenSSL::BN.new(SecureRandom.hex(16), 16)
          cert.subject = subject_name
          cert.issuer = cert.subject
          cert.public_key = public_key_for(key)
          cert.not_before = now - 300
          cert.not_after = now + (validity_days * 86_400)

          factory = OpenSSL::X509::ExtensionFactory.new
          factory.subject_certificate = cert
          factory.issuer_certificate = cert

          [
            factory.create_extension('basicConstraints', 'CA:FALSE', true),
            factory.create_extension('keyUsage', 'digitalSignature,keyEncipherment', true),
            factory.create_extension('extendedKeyUsage', 'serverAuth,clientAuth', false),
            factory.create_extension('subjectKeyIdentifier', 'hash', false),
            factory.create_extension('subjectAltName', desired_names.map { |n| "DNS:#{n}" }.join(','), false),
          ].each { |ext| cert.add_extension(ext) }

          cert.sign(key, digest)
          cert
        end

        # @return [Integer]
        def validity_days
          config['validity_days'] || 365
        end
      end
    end
  end
end
