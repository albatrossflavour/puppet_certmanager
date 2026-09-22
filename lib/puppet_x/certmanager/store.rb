# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'openssl'
require 'time'

require_relative 'paths'
require_relative 'parser'

module PuppetX
  module Certmanager
    # The canonical certificate store.
    #
    # Every issuer backend hands its output to this class and this class
    # decides where it lands, what permissions it gets and whether anything
    # actually changed. Consuming configuration points at these paths and
    # never has to know which CA signed what.
    class Store
      # Files that must not be world readable.
      PRIVATE = [:privkey, :combined, :pkcs12].freeze

      attr_reader :name, :paths

      # @param name [String] certificate name
      def initialize(name)
        @name = name
        @paths = Paths.certificate(name)
      end

      # @return [Boolean] true when a leaf certificate is present
      def exist?
        File.file?(paths[:cert]) && File.file?(paths[:privkey])
      end

      # Parsed description of what is currently in the store.
      #
      # @param now [Time]
      # @return [Hash, nil]
      def info(now: Time.now)
        Parser.parse(paths[:cert], now: now)
      end

      # SHA-256 fingerprint of the certificate currently in the store, used
      # to decide whether a deploy actually changed anything.
      #
      # @return [String, nil]
      def fingerprint
        info&.fetch('fingerprint_sha256', nil)
      end

      # Install a certificate into the store.
      #
      # Writes every file atomically, derives the combined and PKCS#12
      # bundles, records metadata, and fires the deploy hooks only when the
      # leaf certificate actually changed. Returns whether it changed, so
      # the caller can decide whether to report a corrective change.
      #
      # @param cert [String] leaf certificate, PEM
      # @param key [String] private key, PEM
      # @param chain [String] intermediates, PEM. Empty for self-signed.
      # @param issuer [String] issuer instance name, recorded in metadata
      # @param backend [String] backend implementation, recorded in metadata
      # @param renew_before_days [Integer] renewal window, recorded in metadata
      # @param pkcs12_password [String, nil] omit to skip the PKCS#12 bundle
      # @param run_hooks [Boolean] fire deploy hooks on change
      # @return [Boolean] true when the leaf certificate changed
      def deploy(cert:, key:, chain: '', issuer: 'unknown', backend: 'unknown',
                 renew_before_days: 30, pkcs12_password: nil, run_hooks: true)
        previous = fingerprint

        FileUtils.mkdir_p(paths[:dir], mode: 0o755)

        chain = chain.to_s
        fullchain = "#{[cert.strip, chain.strip].reject(&:empty?).join("\n")}\n"

        write(:cert, "#{cert.strip}\n")
        write(:chain, chain.empty? ? '' : "#{chain.strip}\n")
        write(:fullchain, fullchain)
        write(:privkey, "#{key.strip}\n")
        write(:combined, "#{key.strip}\n#{fullchain}")
        write_pkcs12(cert: cert, key: key, chain: chain, password: pkcs12_password)

        write_metadata(issuer: issuer, backend: backend, renew_before_days: renew_before_days)

        changed = previous != fingerprint
        hooks(reason: previous.nil? ? 'issued' : 'renewed') if changed && run_hooks
        changed
      end

      # Install from files an issuer backend produced elsewhere, which is how
      # certbot works: it owns its own directory and its own renewal, we just
      # mirror the result into the canonical layout.
      #
      # @param cert [String] path to the leaf certificate
      # @param key [String] path to the private key
      # @param chain [String, nil] path to the intermediate chain
      # @param issuer [String]
      # @param backend [String]
      # @param renew_before_days [Integer]
      # @param pkcs12_password [String, nil]
      # @return [Boolean] true when the leaf certificate changed
      def deploy_files(cert:, key:, chain: nil, issuer: 'unknown', backend: 'unknown',
                       renew_before_days: 30, pkcs12_password: nil)
        deploy(
          cert: File.read(cert),
          key: File.read(key),
          chain: (chain && File.file?(chain)) ? File.read(chain) : '',
          issuer: issuer,
          backend: backend,
          renew_before_days: renew_before_days,
          pkcs12_password: pkcs12_password,
        )
      end

      # Re-deploy from an ACME client's own directory, preserving whatever
      # was recorded about the certificate last time.
      #
      # This is the out-of-band renewal path: certbot renewed on its timer,
      # Puppet is not running, and nothing here knows which issuer instance
      # or renewal window was declared. Carrying the previous metadata
      # forward keeps the fact honest until the next Puppet run confirms it.
      #
      # @param cert [String] path to the renewed leaf certificate
      # @param key [String] path to the renewed private key
      # @param chain [String, nil] path to the renewed chain
      # @return [Boolean] true when the store changed
      def refresh_from(cert:, key:, chain: nil)
        previous = metadata

        deploy_files(
          cert: cert,
          key: key,
          chain: chain,
          issuer: previous['issuer'] || 'unknown',
          backend: previous['backend'] || 'acme',
          renew_before_days: previous['renew_before_days'] || 30,
        )
      end

      # What the module recorded about this certificate when it deployed it.
      #
      # The store is deliberately self-describing. The provider's `get` runs
      # with no access to the catalog, so without this it could not tell a
      # bootstrap placeholder from a genuinely self-signed certificate, nor
      # know what renewal window was declared. Credentials are never written
      # here, only the facts needed to judge the certificate.
      #
      # @return [Hash]
      def metadata
        JSON.parse(File.read(paths[:metadata]))
      rescue SystemCallError, IOError, JSON::ParserError
        {}
      end

      # Remove the certificate from the store.
      #
      # @return [void]
      def remove
        FileUtils.rm_rf(paths[:dir])
      end

      # Run every deploy hook registered for this certificate.
      #
      # Hooks are best effort by design. A broken reload script for one
      # service must not stop the other services on the host picking up a
      # renewed certificate, and it must not fail the Puppet run that
      # renewed it. Failures are returned for the caller to log.
      #
      # @param reason [String] passed to hooks as CERTMANAGER_REASON
      # @return [Array<String>] names of hooks that exited non-zero
      def hooks(reason: 'deployed')
        dir = File.join(Paths.hook_dir, name)
        return [] unless File.directory?(dir)

        env = {
          'CERTMANAGER_NAME' => name,
          'CERTMANAGER_REASON' => reason,
        }.merge(paths.transform_keys { |k| "CERTMANAGER_#{k.to_s.upcase}" })

        scripts = Dir.glob(File.join(dir, '*')).reject { |hook| File.directory?(hook) }.sort
        failed = scripts.reject { |hook| system(env, hook) }
        failed.map { |hook| File.basename(hook) }
      end

      private

      # Atomic write: temp file in the same directory, permissions set before
      # the rename, then rename over the target. A reader either sees the old
      # file or the new one, never a half-written key.
      #
      # @param key [Symbol] which file in the layout
      # @param content [String]
      # @return [void]
      def write(key, content)
        target = paths[key]

        if content.empty?
          File.delete(target) if File.file?(target)
          return
        end

        mode = PRIVATE.include?(key) ? 0o600 : 0o644
        tmp = "#{target}.tmp-#{Process.pid}"

        File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, mode) do |f|
          f.write(content)
          f.flush
          f.fsync
        end
        File.chmod(mode, tmp)
        File.rename(tmp, target)
      ensure
        File.delete(tmp) if tmp && File.file?(tmp)
      end

      # @return [void]
      def write_pkcs12(cert:, key:, chain:, password:)
        return write(:pkcs12, '') if password.nil? || password.empty?

        ca = chain.to_s.scan(%r{-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----}m)
                  .map { |pem| OpenSSL::X509::Certificate.new(pem) }

        p12 = OpenSSL::PKCS12.create(
          password,
          name,
          OpenSSL::PKey.read(key),
          OpenSSL::X509::Certificate.new(cert),
          ca,
        )
        write(:pkcs12, p12.to_der)
      rescue OpenSSL::OpenSSLError => e
        raise "certmanager: could not build PKCS#12 bundle for #{name}: #{e.message}"
      end

      # @return [void]
      def write_metadata(issuer:, backend:, renew_before_days:)
        parsed = Parser.parse(paths[:cert]) || {}

        record = {
          'name' => name,
          'issuer' => issuer,
          'backend' => backend,
          'renew_before_days' => renew_before_days,
          'deployed_at' => Time.now.utc.iso8601,
          'serial' => parsed['serial'],
          'not_after' => parsed['not_after'],
          'fingerprint_sha256' => parsed['fingerprint_sha256'],
          'san' => parsed['san'],
        }

        write(:metadata, "#{JSON.pretty_generate(record)}\n")
      end
    end
  end
end
