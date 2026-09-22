# frozen_string_literal: true

require 'openssl'

require_relative '../paths'
require_relative '../store'

module PuppetX
  module Certmanager
    module Issuer
      # Common behaviour for every issuer backend.
      #
      # Subclasses implement #issue and, where the CA supports it, #revoke.
      # Everything else, including the decision about *whether* to issue, is
      # settled here so the three backends can't drift apart on it.
      class Base
        # Raised when a backend cannot complete an operation. The provider
        # turns this into a Puppet failure for the one resource rather than
        # aborting the run.
        class Error < StandardError; end

        # OpenSSL's names for the curves behind the key types this module
        # accepts. Anything not listed falls back to P-256, which is what
        # every CA and every TLS stack in service supports.
        CURVES = {
          'ecdsa-p256' => 'prime256v1',
          'ecdsa-p384' => 'secp384r1',
          'ecdsa-p521' => 'secp521r1',
        }.freeze

        attr_reader :name, :resource, :config, :store

        # @param name [String] certificate name
        # @param resource [Hash] the certmanager_certificate resource
        # @param config [Hash] the issuer instance's configuration
        def initialize(name, resource, config)
          @name = name
          @resource = resource
          @config = config
          @store = Store.new(name)
        end

        # Whether the certificate in the store satisfies what was declared.
        #
        # This is the whole idempotency story. A certificate is not a normal
        # resource: it is correct or not based on time and on content, not on
        # simple presence, so `exists?` alone would never renew anything.
        #
        # @param now [Time]
        # @return [Array<String>] reasons to reissue; empty means leave it alone
        def drift(now: Time.now)
          return ['no certificate in the store'] unless store.exist?

          info = store.info(now: now)
          return ['certificate in the store is unreadable'] if info.nil?

          reasons = []
          reasons << "expires in #{info['days_left']} days" if info['days_left'] <= renew_before_days
          reasons << 'bootstrap placeholder still in place' if info['self_signed'] && backend != 'selfsigned'

          wanted = desired_names
          reasons << "names changed (#{info['san'].join(',')} -> #{wanted.join(',')})" if info['san'] != wanted

          key_type = resource[:key_type]
          reasons << "key type changed (#{info['key_type']} -> #{key_type})" if key_type && info['key_type'] != key_type

          reasons
        end

        # Every DNS name that should appear on the certificate, sorted so the
        # comparison against the parsed SAN list is order-insensitive.
        #
        # The common name is included: a CA that still honours CN will put it
        # in the SAN list as well, and every CA has done so since 2017.
        #
        # @return [Array<String>]
        def desired_names
          ([resource[:common_name]] + Array(resource[:san])).compact.uniq.sort
        end

        # @return [Integer] days before expiry at which to renew
        def renew_before_days
          resource[:renew_before_days] || 30
        end

        # Name of the backend implementation, as opposed to the issuer
        # instance name.
        #
        # @return [String]
        def backend
          self.class.name.split('::').last.downcase
        end

        # The metadata every backend records alongside a deployed
        # certificate, so the provider can judge it later without the
        # catalog in hand.
        #
        # @return [Hash]
        def store_metadata
          {
            issuer: resource[:issuer] || backend,
            backend: backend,
            renew_before_days: renew_before_days,
            pkcs12_password: secret(resource[:pkcs12_password]),
          }
        end

        # True when renewal happens outside Puppet, on the backend's own
        # timer. Puppet still owns issuance and configuration, but must not
        # treat "certbot renewed it an hour ago" as drift.
        #
        # @return [Boolean]
        def external_renewal?
          false
        end

        # Issue or renew the certificate and deploy it into the store.
        #
        # @return [void]
        def issue
          raise NotImplementedError, "#{self.class} does not implement #issue"
        end

        # Revoke the certificate with the CA, where the CA has a concept of
        # revocation. Removing the files is the caller's job.
        #
        # @return [void]
        def revoke
          nil
        end

        private

        # Generate a private key of the declared type.
        #
        # @return [OpenSSL::PKey::PKey]
        def generate_key
          declared = resource[:key_type].to_s
          return OpenSSL::PKey::RSA.new(Regexp.last_match(1).to_i) if declared =~ %r{\Arsa-(\d+)\z}

          OpenSSL::PKey::EC.generate(CURVES.fetch(declared, 'prime256v1'))
        end

        # Build a CSR covering every desired name.
        #
        # @param key [OpenSSL::PKey::PKey]
        # @return [OpenSSL::X509::Request]
        def build_csr(key)
          csr = OpenSSL::X509::Request.new
          csr.version = 0
          csr.subject = subject_name
          csr.public_key = public_key_for(key)

          factory = OpenSSL::X509::ExtensionFactory.new
          san = desired_names.map { |n| "DNS:#{n}" }.join(',')
          extensions = [factory.create_extension('subjectAltName', san, false)]

          attribute = OpenSSL::X509::Attribute.new(
            'extReq',
            OpenSSL::ASN1::Set.new([OpenSSL::ASN1::Sequence.new(extensions)]),
          )
          csr.add_attribute(attribute)
          csr.sign(key, digest)
          csr
        end

        # The public half of a key pair, as a key object safe to hand to a
        # certificate or a CSR.
        #
        # A generated key carries its private component, and assigning it
        # straight onto a certificate embeds the lot. The obvious fix, build
        # an empty key and set `public_key=`, stopped working at OpenSSL 3.0
        # where pkeys became immutable. Round-tripping through the DER
        # encoding of the public key is the supported way and works for
        # every algorithm.
        #
        # @param key [OpenSSL::PKey::PKey]
        # @return [OpenSSL::PKey::PKey]
        def public_key_for(key)
          return OpenSSL::PKey.read(key.public_to_der) if key.respond_to?(:public_to_der)

          # openssl gem older than 2.2, which predates the immutability
          # change, so the mutable path is still available there.
          key.is_a?(OpenSSL::PKey::EC) ? key : key.public_key
        end

        # @return [OpenSSL::X509::Name]
        def subject_name
          components = [['CN', resource[:common_name] || name, OpenSSL::ASN1::UTF8STRING]]

          (resource[:subject] || {}).each do |field, value|
            components << [field.to_s, value.to_s, OpenSSL::ASN1::UTF8STRING]
          end

          OpenSSL::X509::Name.new(components)
        end

        # @return [OpenSSL::Digest]
        def digest
          case config['signature_hash']
          when 'sha384' then OpenSSL::Digest.new('SHA384')
          when 'sha512' then OpenSSL::Digest.new('SHA512')
          else OpenSSL::Digest.new('SHA256')
          end
        end

        # Resolve a credential that may be a plain string, a Puppet Sensitive
        # already unwrapped by the resource API, or nil.
        #
        # @param value [Object]
        # @return [String, nil]
        def secret(value)
          return nil if value.nil?
          return value.unwrap if value.respond_to?(:unwrap)

          value.to_s
        end
      end
    end
  end
end
