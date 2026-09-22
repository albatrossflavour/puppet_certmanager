# frozen_string_literal: true

# Line coverage for the Ruby that does the actual work. Most of this module
# is types, providers, issuer backends and a fact, so resource coverage on
# its own says very little about whether any of it is tested.
#
# Started here rather than in spec_helper.rb because that file is
# PDK-managed, and before anything under lib/ is required, or SimpleCov
# records nothing.
if ENV['COVERAGE'] == 'yes'
  require 'simplecov'
  require 'simplecov-console'

  SimpleCov.formatters = [
    SimpleCov::Formatter::HTMLFormatter,
    SimpleCov::Formatter::Console,
  ]

  SimpleCov.start do
    track_files 'lib/**/*.rb'
    # The pdctng collector ships from files/ because pdctng copies it into
    # its own plugin directory rather than loading it from the modulepath.
    # It is still this module's Ruby and still has to be tested.
    track_files 'files/**/*.rb'
    add_filter '/spec/'
    add_filter '/vendor/'

    # Loaded only by Puppet's own autoloader, out of the modulepath, which
    # means the fixtures symlink rather than lib/. SimpleCov tracks the
    # lib/ copy, nothing ever executes it, and it reports 0% no matter how
    # well tested it is.
    #
    # These are not untested. The three functions have 19 examples in
    # spec/functions that exercise every component, every error and the
    # Windows layout, and the two type files are declarations that fail the
    # whole suite the moment they are wrong. They are excluded because the
    # measurement cannot see them, not because nobody looked.
    add_filter 'lib/puppet/functions'
    add_filter 'lib/puppet/type'
    add_group 'Types and providers', 'lib/puppet'
    add_group 'Libraries', 'lib/puppet_x'
    add_group 'Facts', 'lib/facter'
    add_group 'Integrations', 'files'

    # Measured over spec/unit only, and that is load-bearing rather than a
    # convenience. spec/fixtures/modules/certmanager symlinks to the module
    # root, so a catalogue compile loads providers through a second path
    # and the calls land on a copy SimpleCov is not tracking. Run with the
    # whole suite the certificate provider reports 29%; run over spec/unit
    # it reports 97%, with the same tests and the same code.
    minimum_coverage Integer(ENV.fetch('COVERAGE_MINIMUM', 95))
  end
end

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
