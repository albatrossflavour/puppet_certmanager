# frozen_string_literal: true

require 'fileutils'
require 'open3'

require_relative 'base'

module PuppetX
  module Certmanager
    module Issuer
      # ACME issuance, wrapping certbot on POSIX and win-acme on Windows.
      #
      # The client owns its own account state and its own renewal timer, and
      # that is deliberate: reimplementing ACME in a Puppet provider would
      # mean reimplementing account key rotation, nonce handling and retry
      # backoff, all of which certbot already gets right.
      #
      # So Puppet owns configuration and first issuance, the client owns
      # renewal, and the store is mirrored from the client's output. The
      # deploy hook installed alongside keeps the store current when a
      # renewal happens between Puppet runs.
      class Acme < Base
        # Renewal is certbot's job, on its own timer.
        #
        # @return [Boolean]
        def external_renewal?
          true
        end

        # @return [void]
        def issue
          Paths.windows? ? issue_win_acme : issue_certbot
          sync
        end

        # Mirror the client's output into the canonical store.
        #
        # Separate from #issue because the common case is that nothing needs
        # issuing: certbot renewed on its timer and Puppet is just noticing.
        #
        # @return [Boolean] true when the store changed
        def sync
          source = client_paths
          raise Error, "certmanager: #{name} was issued but no certificate appeared at #{source[:cert]}" unless File.file?(source[:cert])

          store.deploy_files(cert: source[:cert], key: source[:key], chain: source[:chain], **store_metadata)
        end

        # @return [void]
        def revoke
          return if Paths.windows?

          run(certbot, 'revoke', '--non-interactive',
              '--cert-path', client_paths[:cert],
              '--reason', resource[:revocation_reason] || 'unspecified',
              *server_args)
        end

        private

        # Where the ACME client leaves its output. certbot organises by
        # lineage name; win-acme writes flat files into a directory we
        # choose, named by a prefix.
        #
        # @return [Hash{Symbol => String}]
        def client_paths
          if Paths.windows?
            dir = File.join(Paths.state_dir, 'win-acme', name)
            { cert: File.join(dir, "#{name}-crt.pem"),
              key: File.join(dir, "#{name}-key.pem"),
              chain: File.join(dir, "#{name}-chain-only.pem") }
          else
            dir = File.join(config_dir, 'live', name)
            { cert: File.join(dir, 'cert.pem'),
              key: File.join(dir, 'privkey.pem'),
              chain: File.join(dir, 'chain.pem') }
          end
        end

        # @return [String]
        def config_dir
          config['config_dir'] || '/etc/letsencrypt'
        end

        # @return [String]
        def certbot
          config['certbot_path'] || 'certbot'
        end

        # @return [void]
        def issue_certbot
          args = ['certonly', '--non-interactive', '--agree-tos', '--keep-until-expiring',
                  '--cert-name', name]
          args += server_args
          args += account_args
          args += desired_names.flat_map { |n| ['-d', n] }
          args += key_args
          args += challenge_args
          args += ['--preferred-chain', config['preferred_chain']] if config['preferred_chain']
          args << '--force-renewal' if resource[:force_renewal]

          run(certbot, *args)
        end

        # @return [void]
        def issue_win_acme
          dir = File.dirname(client_paths[:cert])
          FileUtils.mkdir_p(dir)

          args = ['--source', 'manual', '--host', desired_names.join(','),
                  '--friendlyname', name,
                  '--store', 'pemfiles', '--pemfilespath', dir, '--pemfilesname', name,
                  '--accepttos', '--notaskscheduler']
          args += ['--emailaddress', config['email']] if config['email']
          args += ['--baseuri', config['directory_url']] if config['directory_url']
          args += ['--eab-key-identifier', config['eab_kid']] if config['eab_kid']
          args += ['--eab-key', secret(config['eab_hmac_key'])] if config['eab_hmac_key']
          args += win_acme_challenge_args
          args << '--force' if resource[:force_renewal]

          run(config['wacs_path'] || 'wacs.exe', *args)
        end

        # @return [Array<String>]
        def server_args
          config['directory_url'] ? ['--server', config['directory_url']] : []
        end

        # @return [Array<String>]
        def account_args
          args = []
          args += ['--config-dir', config_dir] if config['config_dir']

          if config['email'].to_s.empty?
            args << '--register-unsafely-without-email'
          else
            args += ['--email', config['email']]
          end

          if config['eab_kid']
            args += ['--eab-kid', config['eab_kid'],
                     '--eab-hmac-key', secret(config['eab_hmac_key']).to_s]
          end

          args
        end

        # @return [Array<String>]
        def key_args
          case resource[:key_type].to_s
          when %r{\Arsa-(\d+)\z}
            ['--key-type', 'rsa', '--rsa-key-size', Regexp.last_match(1)]
          when 'ecdsa-p384'
            ['--key-type', 'ecdsa', '--elliptic-curve', 'secp384r1']
          else
            ['--key-type', 'ecdsa', '--elliptic-curve', 'secp256r1']
          end
        end

        # The challenge actually in play: the resource wins, then the
        # issuer's default, then http-01.
        #
        # @return [String]
        def challenge
          resource[:challenge] || config['challenge'] || 'http-01'
        end

        # @return [Array<String>]
        def challenge_args
          case challenge
          when 'dns-01' then dns_args
          when 'tls-alpn-01' then ['--standalone', '--preferred-challenges', 'tls-alpn-01']
          else http_args
          end
        end

        # @return [Array<String>]
        def http_args
          webroot = resource[:webroot] || config['webroot']
          return ['--webroot', '--webroot-path', webroot, '--preferred-challenges', 'http-01'] if webroot

          args = ['--standalone', '--preferred-challenges', 'http-01']
          args += ['--http-01-port', config['server_port'].to_s] if config['server_port']
          args
        end

        # DNS validation. The propagation wait is the thing that actually
        # matters here: certbot's defaults are tuned for the provider's
        # best case, and a slow zone transfer means the CA looks before the
        # record exists.
        #
        # @return [Array<String>]
        def dns_args
          plugin = config['dns_plugin']
          raise Error, "certmanager: issuer for #{name} uses dns-01 but sets no dns_plugin" if plugin.to_s.empty?

          args = ["--dns-#{plugin}"]

          args += ["--dns-#{plugin}-credentials", credential_file] if config['dns_credentials']

          args += ["--dns-#{plugin}-propagation-seconds", config['dns_propagation_seconds'].to_s] if config['dns_propagation_seconds']

          args
        end

        # @return [Array<String>]
        def win_acme_challenge_args
          case challenge
          when 'dns-01'
            ['--validation', config['dns_plugin'] || 'dnsscript']
          else
            webroot = resource[:webroot] || config['webroot']
            webroot ? ['--validation', 'filesystem', '--webroot', webroot] : ['--validation', 'selfhosting']
          end
        end

        # Credential file for the DNS plugin, written by the manifest at
        # mode 0600. certbot refuses to use a credentials file that is
        # group or world readable, which is a nuisance the first time and
        # correct every time after that.
        #
        # @return [String]
        def credential_file
          File.join(Paths.credential_dir, "#{resource[:issuer] || 'acme'}.ini")
        end

        # Run a command, capturing output so a failure reports what the
        # client actually said rather than just an exit status.
        #
        # @param command [Array<String>]
        # @return [String] combined output
        def run(*command)
          # stdin_data closes the child's stdin. Puppet runs with stdin
          # attached to whatever invoked the agent, and a Bolt task's stdin
          # is the parameter pipe; handing either to certbot is a good way
          # to find out which tools block on it.
          output, status = Open3.capture2e(*command, stdin_data: '')
          return output if status.success?

          raise Error, "certmanager: #{File.basename(command.first)} failed for #{name} " \
                       "(exit #{status.exitstatus}): #{output.strip}"
        rescue Errno::ENOENT
          raise Error, "certmanager: #{command.first} is not installed or not on PATH"
        end
      end
    end
  end
end
