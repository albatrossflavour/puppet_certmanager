# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'

require_relative 'paths'
require_relative 'parser'

module PuppetX
  module Certmanager
    # Builds the certificate inventory that backs the `certmanager` fact.
    #
    # Two sources. The store, which is everything this module issued and
    # owns. And a configurable scan of other directories, which is where the
    # value actually is: the certificate nobody remembers deploying, sitting
    # in /etc/pki since 2019, is the one that takes the service down.
    module Inventory
      # Certificate file extensions worth opening. Deliberately excludes
      # .key: a scan that reads private keys and reports on them is a
      # liability, not a feature.
      EXTENSIONS = ['.pem', '.crt', '.cer'].freeze

      # Upper bound on files opened in one scan. A misconfigured scan
      # directory pointed at /etc/ssl/certs finds several hundred CA roots
      # and turns a fact into a two second stall on every run.
      MAX_FILES = 2000

      module_function

      # Build the inventory.
      #
      # @param config [Hash] scan configuration, normally from scan_config
      # @param now [Time]
      # @return [Hash]
      def build(config = scan_config, now: Time.now)
        certificates = {}

        managed(now: now).each { |name, entry| certificates[name] = entry }

        scanned(config, now: now).each do |name, entry|
          # A certificate found by the scan never displaces a managed one.
          certificates[name] ||= entry
        end

        summarise(certificates, config, now: now)
      end

      # Certificates in the canonical store.
      #
      # @param now [Time]
      # @return [Hash]
      def managed(now: Time.now)
        root = Paths.store_dir
        return {} unless File.directory?(root)

        Dir.children(root).sort.each_with_object({}) do |name, acc|
          paths = Paths.certificate(name)
          info = Parser.parse(paths[:cert], now: now)
          next if info.nil?

          metadata = read_json(paths[:metadata])

          acc[name] = info.merge(
            'managed' => true,
            'issuer' => metadata['issuer'] || 'unknown',
            'backend' => metadata['backend'],
            'consumers' => consumers(name),
          )
        end
      end

      # Certificates found elsewhere on the filesystem.
      #
      # @param config [Hash]
      # @param now [Time]
      # @return [Hash]
      def scanned(config, now: Time.now)
        directories = Array(config['scan_directories'])
        return {} if directories.empty?

        store_root = Paths.store_dir
        budget = MAX_FILES

        directories.each_with_object({}) do |dir, acc|
          next unless File.directory?(dir)

          candidates(dir, config).each do |file|
            break if budget <= 0
            next if file.start_with?(store_root)

            budget -= 1
            info = Parser.parse(file, now: now)
            next if info.nil?
            next if config['ignore_ca_certificates'] && ca_certificate?(info)

            key = info['subject'][%r{CN=([^,]+)}, 1] || File.basename(file)
            acc[key] ||= info.merge('managed' => false, 'issuer' => 'unknown', 'backend' => nil, 'consumers' => [])
          end
        end
      end

      # Services registered against a certificate.
      #
      # Derived from the hook directory rather than from anything Puppet
      # writes separately: certmanager::consumer already has to put a script
      # there for out-of-band renewals, so that directory is the one place
      # that cannot go stale relative to reality.
      #
      # @param name [String]
      # @return [Array<String>]
      def consumers(name)
        dir = File.join(Paths.hook_dir, name)
        return [] unless File.directory?(dir)

        Dir.children(dir).reject { |c| File.directory?(File.join(dir, c)) }.sort
      end

      # @param dir [String]
      # @param config [Hash]
      # @return [Array<String>]
      def candidates(dir, config)
        pattern = config['scan_recursive'] ? File.join(dir, '**', '*') : File.join(dir, '*')

        Dir.glob(pattern).select { |file|
          File.file?(file) && EXTENSIONS.include?(File.extname(file).downcase)
        }.sort
      end

      # A CA certificate in a trust bundle is not something anyone renews,
      # and reporting a few hundred of them buries the one certificate that
      # matters.
      #
      # @param info [Hash]
      # @return [Boolean]
      def ca_certificate?(info)
        info['self_signed'] && info['san'].empty?
      end

      # Roll the per-certificate detail up into the shape the fact exposes.
      #
      # @param certificates [Hash]
      # @param config [Hash]
      # @param now [Time]
      # @return [Hash]
      def summarise(certificates, config, now: Time.now)
        live = certificates.reject { |_, cert| cert['expired'] }

        critical = within(live, config['critical_days'] || 7)
        warning = within(live, config['warn_days'] || 30) - critical

        {
          'certificates' => certificates,
          'count' => certificates.size,
          'managed_count' => certificates.count { |_, cert| cert['managed'] },
          'expired' => certificates.select { |_, cert| cert['expired'] }.keys.sort,
          'expiring_critical' => critical,
          'expiring_soon' => warning,
          # A self-signed certificate is only a problem when a real CA was
          # supposed to sign it. The bootstrap records itself as
          # `placeholder` at deploy time, so this needs no guessing from the
          # issuer name, which the user is free to call whatever they like.
          'placeholders' => certificates.select { |_, cert| cert['backend'] == 'placeholder' }.keys.sort,
          'soonest_expiry' => live.values.map { |cert| cert['days_left'] }.min,
          'generated_at' => now.utc.iso8601,
        }
      end

      # @param certificates [Hash]
      # @param days [Integer]
      # @return [Array<String>]
      def within(certificates, days)
        certificates.select { |_, cert| cert['days_left'] <= days }.keys.sort
      end

      # Write the inventory to the cache the fact reads.
      #
      # @param inventory [Hash]
      # @return [String] the cache path
      def write_cache(inventory)
        FileUtils.mkdir_p(File.dirname(Paths.cache_file), mode: 0o755)
        tmp = "#{Paths.cache_file}.tmp-#{Process.pid}"
        File.write(tmp, JSON.pretty_generate(inventory))
        File.chmod(0o644, tmp)
        File.rename(tmp, Paths.cache_file)
        Paths.cache_file
      end

      # Scan configuration, written by the manifest.
      #
      # @return [Hash]
      def scan_config
        defaults = {
          'scan_directories' => [],
          'scan_recursive' => false,
          'ignore_ca_certificates' => true,
          'warn_days' => 30,
          'critical_days' => 7,
          'cache_max_age_hours' => 24,
        }
        defaults.merge(read_json(File.join(Paths.root, 'cache', 'scan.json')))
      end

      # @param path [String]
      # @return [Hash]
      def read_json(path)
        JSON.parse(File.read(path))
      rescue SystemCallError, IOError, JSON::ParserError
        {}
      end
    end
  end
end
