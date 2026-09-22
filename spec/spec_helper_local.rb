# frozen_string_literal: true

require 'fileutils'
require 'openssl'
require 'tmpdir'

# Helpers for the certmanager unit tests.
#
# Certificates are generated on the fly rather than checked in as fixtures.
# A committed certificate expires, and a test suite that starts failing on a
# date nobody wrote down is worse than no test at all.
module CertmanagerSpec
  module_function

  # Build a certificate and key.
  #
  # @param common_name [String] the subject common name
  # @param san [Array<String>] subject alternative names
  # @param days [Integer] validity from now; negative for an expired certificate
  # @param key_type [String] certmanager key type name
  # @param issuer [OpenSSL::X509::Certificate, nil] signing certificate, for a chain
  # @param issuer_key [OpenSSL::PKey::PKey, nil] signing key
  # @return [Array(OpenSSL::X509::Certificate, OpenSSL::PKey::PKey)]
  def certificate(common_name: 'www.example.com', san: [], days: 90, key_type: 'ecdsa-p256',
                  issuer: nil, issuer_key: nil)
    key = key_for(key_type)
    cert = shell(common_name: common_name, key: key, issuer: issuer, days: days)

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert

    names = ([common_name] + san).uniq.map { |name| "DNS:#{name}" }.join(',')
    cert.add_extension(factory.create_extension('subjectAltName', names))
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))

    cert.sign(issuer_key || key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end

  # The certificate before any extensions or signature.
  #
  # @return [OpenSSL::X509::Certificate]
  def shell(common_name:, key:, issuer:, days:)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.new(SecureRandom.hex(8), 16)
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{common_name}")
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = OpenSSL::PKey.read(key.public_to_der)
    cert.not_before = Time.now - 3600
    # An hour of slack past the requested window. Without it the seconds
    # spent generating and writing the certificate push it just under the
    # day boundary, and `days_left` comes back one short at random.
    cert.not_after = Time.now + (days * 86_400) + 3600
    cert
  end

  # @param key_type [String] certmanager key type name
  # @return [OpenSSL::PKey::PKey]
  def key_for(key_type)
    case key_type
    when 'ecdsa-p384' then OpenSSL::PKey::EC.generate('secp384r1')
    when 'rsa-2048' then OpenSSL::PKey::RSA.new(2048)
    else OpenSSL::PKey::EC.generate('prime256v1')
    end
  end

  # Build a CA certificate, for chain tests.
  #
  # @return [Array(OpenSSL::X509::Certificate, OpenSSL::PKey::PKey)]
  def ca(common_name: 'Test Intermediate CA')
    key = OpenSSL::PKey::EC.generate('prime256v1')
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{common_name}")
    cert.issuer = cert.subject
    cert.public_key = OpenSSL::PKey.read(key.public_to_der)
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + (3650 * 86_400)

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end
end

RSpec.configure do |config|
  # Every example gets its own store, so nothing leaks between tests and
  # nothing touches the machine running the suite.
  config.around(:each, :store) do |example|
    Dir.mktmpdir('certmanager-spec') do |dir|
      previous = ENV.fetch('CERTMANAGER_ROOT', nil)
      ENV['CERTMANAGER_ROOT'] = dir
      begin
        example.run
      ensure
        ENV['CERTMANAGER_ROOT'] = previous
      end
    end
  end
end
