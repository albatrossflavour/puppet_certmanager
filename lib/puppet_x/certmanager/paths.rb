# frozen_string_literal: true

require 'rbconfig'

# Namespace for module-shipped Ruby libraries, as Puppet's own convention
# has it.
module PuppetX
  # Everything certmanager ships that is not a type, provider, function or
  # fact. Loaded by pluginsync on the agent, and directly by the Bolt tasks
  # and the deploy hook, which run with no Puppet around them at all.
  module Certmanager
    # Where certmanager keeps its things.
    #
    # Deliberately has no Puppet dependency: the custom fact loads this on a
    # bare agent run with nothing else in scope, and the Bolt tasks load it
    # outside a catalog altogether.
    module Paths
      module_function

      # @return [Boolean] true when running on Windows
      def windows?
        !(RbConfig::CONFIG['host_os'] =~ %r{mswin|mingw|cygwin}).nil?
      end

      # Root of everything this module owns.
      #
      # Overridable through CERTMANAGER_ROOT so the unit tests and the Bolt
      # tasks can point at a scratch directory without monkeypatching.
      #
      # @return [String]
      def root
        return ENV.fetch('CERTMANAGER_ROOT', nil) unless ENV['CERTMANAGER_ROOT'].nil? || ENV['CERTMANAGER_ROOT'].empty?

        windows? ? 'C:/ProgramData/PuppetLabs/certmanager' : '/etc/certmanager'
      end

      # The canonical certificate store. One directory per certificate.
      #
      # @return [String]
      def store_dir
        File.join(root, 'certs')
      end

      # Deploy hook scripts, one directory per certificate.
      #
      # @return [String]
      def hook_dir
        File.join(root, 'hooks')
      end

      # Issuer working state: ACME accounts, DigiCert order records, the
      # cached CSRs. Not world readable.
      #
      # @return [String]
      def state_dir
        File.join(root, 'state')
      end

      # Credential files written for issuer backends (DNS plugin creds and
      # the like). Mode 0600, never in the store.
      #
      # @return [String]
      def credential_dir
        File.join(root, 'credentials')
      end

      # Cache the fact reads. Written by the refresh task, not by the fact
      # itself, so a Puppet run never blocks on parsing a few hundred
      # certificates.
      #
      # @return [String]
      def cache_file
        File.join(root, 'cache', 'certificates.json')
      end

      # The files making up one certificate in the store.
      #
      # @param name [String] certificate name
      # @param store [String] the store root, for callers that resolve it
      #   themselves. `certmanager::path()` does, because the store location
      #   is a class parameter a site can override in Hiera and this module
      #   is loaded with no catalogue in sight.
      # @return [Hash{Symbol => String}]
      def certificate(name, store: store_dir)
        dir = File.join(store, name)
        {
          dir: dir,
          cert: File.join(dir, 'cert.pem'),
          chain: File.join(dir, 'chain.pem'),
          fullchain: File.join(dir, 'fullchain.pem'),
          privkey: File.join(dir, 'privkey.pem'),
          combined: File.join(dir, 'combined.pem'),
          pkcs12: File.join(dir, 'bundle.p12'),
          metadata: File.join(dir, 'cert.json'),
        }
      end
    end
  end
end
