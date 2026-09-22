# frozen_string_literal: true

require 'openssl'
require 'time'

module PuppetX
  module Certmanager
    # Turns an X.509 certificate on disk into the flat hash the fact, the
    # provider and the report task all share.
    #
    # No Puppet dependency, for the same reason as Paths.
    module Parser
      module_function

      # Parse a PEM or DER certificate file.
      #
      # Returns nil rather than raising: this runs across whatever happens to
      # be in /etc/pki, and one unreadable file or stray private key should
      # not take the whole fact down.
      #
      # @param path [String] absolute path to a certificate file
      # @param now [Time] reference time, injected so tests aren't racing the clock
      # @return [Hash, nil]
      def parse(path, now: Time.now)
        raw = read(path)
        return nil if raw.nil?

        cert = load_certificate(raw)
        return nil if cert.nil?

        describe(cert, path: path, now: now)
      end

      # @param path [String]
      # @return [String, nil]
      def read(path)
        File.binread(path)
      rescue SystemCallError, IOError
        nil
      end

      # Load the first certificate out of a blob, PEM or DER.
      #
      # A fullchain.pem holds several; the leaf is always first, and the leaf
      # is the one anyone cares about.
      #
      # @param raw [String]
      # @return [OpenSSL::X509::Certificate, nil]
      def load_certificate(raw)
        pem = raw[%r{-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----}m]
        OpenSSL::X509::Certificate.new(pem || raw)
      rescue OpenSSL::X509::CertificateError, ArgumentError, TypeError
        nil
      end

      # Describe a loaded certificate.
      #
      # @param cert [OpenSSL::X509::Certificate]
      # @param path [String]
      # @param now [Time]
      # @return [Hash]
      def describe(cert, path:, now: Time.now)
        not_after = cert.not_after.utc

        {
          'path' => path,
          'subject' => cert.subject.to_utf8,
          'issuer_dn' => cert.issuer.to_utf8,
          'serial' => cert.serial.to_s(16).upcase,
          'san' => subject_alt_names(cert),
          'not_before' => cert.not_before.utc.iso8601,
          'not_after' => not_after.iso8601,
          'days_left' => days_between(now.utc, not_after),
          'expired' => not_after <= now.utc,
          'self_signed' => self_signed?(cert),
          'key_type' => key_type(cert),
          'signature_algorithm' => cert.signature_algorithm,
          'fingerprint_sha256' => fingerprint(cert),
        }
      end

      # DNS names from the subjectAltName extension.
      #
      # IP and email entries are dropped: everything downstream is matching
      # hostnames, and mixing them in makes the SAN comparison in the
      # provider report spurious drift.
      #
      # @param cert [OpenSSL::X509::Certificate]
      # @return [Array<String>]
      def subject_alt_names(cert)
        ext = cert.extensions.find { |e| e.oid == 'subjectAltName' }
        return [] if ext.nil?

        names = ext.value.split(',').filter_map do |entry|
          stripped = entry.strip
          stripped.delete_prefix('DNS:') if stripped.start_with?('DNS:')
        end
        names.sort
      end

      # Whole days from now until expiry, rounded down. Negative once expired.
      #
      # Deliberately not `(a - b) / 86400` on the raw floats: leap seconds and
      # DST make that land on the wrong side of a threshold about twice a year.
      #
      # @param from [Time]
      # @param to [Time]
      # @return [Integer]
      def days_between(from, to)
        ((to.to_i - from.to_i) / 86_400.0).floor
      end

      # A certificate is self-signed when it verifies against its own public
      # key. Comparing subject to issuer is not enough: a cross-signed
      # intermediate can have both the same.
      #
      # @param cert [OpenSSL::X509::Certificate]
      # @return [Boolean]
      def self_signed?(cert)
        cert.subject == cert.issuer && cert.verify(cert.public_key)
      rescue OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError
        false
      end

      # Human-readable key algorithm and size, matching the values accepted
      # by the `key_type` parameter so the fact can be compared to the
      # manifest without translation.
      #
      # @param cert [OpenSSL::X509::Certificate]
      # @return [String]
      def key_type(cert)
        key = cert.public_key

        case key
        when OpenSSL::PKey::RSA
          "rsa-#{key.n.num_bits}"
        when OpenSSL::PKey::EC
          curve = { 'prime256v1' => 'p256', 'secp384r1' => 'p384', 'secp521r1' => 'p521' }
          "ecdsa-#{curve.fetch(key.group.curve_name, key.group.curve_name)}"
        when OpenSSL::PKey::DSA
          "dsa-#{key.p.num_bits}"
        else
          'unknown'
        end
      rescue OpenSSL::PKey::PKeyError, NotImplementedError
        'unknown'
      end

      # @param cert [OpenSSL::X509::Certificate]
      # @return [String] colon-separated uppercase hex
      def fingerprint(cert)
        OpenSSL::Digest::SHA256.hexdigest(cert.to_der).upcase.scan(%r{..}).join(':')
      end
    end
  end
end
