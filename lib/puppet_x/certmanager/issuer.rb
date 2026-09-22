# frozen_string_literal: true

require_relative 'issuer/acme'
require_relative 'issuer/digicert'
require_relative 'issuer/selfsigned'

module PuppetX
  module Certmanager
    # Resolves a backend name to its implementation.
    module Issuer
      BACKENDS = {
        'acme' => Acme,
        'digicert' => Digicert,
        'selfsigned' => Selfsigned,
      }.freeze

      module_function

      # @param name [String] certificate name
      # @param resource [Hash] the certmanager_certificate resource
      # @return [PuppetX::Certmanager::Issuer::Base]
      def for(name, resource)
        config = resource[:issuer_config] || {}
        backend = config['backend'] || config[:backend] || 'selfsigned'

        klass = BACKENDS[backend.to_s]
        raise Base::Error, "certmanager: unknown issuer backend '#{backend}' for #{name}" if klass.nil?

        klass.new(name, resource, stringify(config))
      end

      # The resource API hands hashes through with symbol keys in some code
      # paths and string keys in others depending on whether the value came
      # from the catalog or from a task. Normalise once, here.
      #
      # @param hash [Hash]
      # @return [Hash]
      def stringify(hash)
        hash.transform_keys(&:to_s)
      end
    end
  end
end
