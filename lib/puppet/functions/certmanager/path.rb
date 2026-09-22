# frozen_string_literal: true

# Namespace for constants shared by this module's Puppet functions. Puppet
# functions are created inside a block, and a constant defined in that block
# lands in the wrong namespace and is redefined on every reload, so anything
# they share lives out here.
module Certmanager
  # Filenames in the certificate store, keyed by the component name the
  # function accepts. Defined outside the function body because a constant
  # inside `create_function`'s block would land in the wrong namespace and
  # be redefined on every reload.
  STORE_FILENAMES = {
    'cert' => 'cert.pem',
    'chain' => 'chain.pem',
    'fullchain' => 'fullchain.pem',
    'privkey' => 'privkey.pem',
    'combined' => 'combined.pem',
    'pkcs12' => 'bundle.p12',
    'metadata' => 'cert.json',
  }.freeze
end

# Returns the canonical path to one file of a managed certificate.
#
# This is how consuming configuration finds a certificate without hardcoding
# a path that is correct only for one issuer. An nginx template calls this
# and keeps working when the certificate moves from Let's Encrypt to
# DigiCert, because the store layout does not change.
#
# The location honours `certmanager::store_dir` from Hiera, so overriding
# the store in data moves the function's answer with it.
#
# @example In an EPP template
#   ssl_certificate     <%= certmanager::path($cert, 'fullchain') %>;
#   ssl_certificate_key <%= certmanager::path($cert, 'privkey') %>;

Puppet::Functions.create_function(:'certmanager::path', Puppet::Functions::InternalFunction) do
  # @param name The certificate name, matching the `certmanager::certificate` title.
  # @param component Which file in the store to return.
  # @return [Stdlib::Absolutepath] Absolute path to that file.
  dispatch :path do
    scope_param
    param 'Certmanager::Certname', :name
    optional_param "Enum['cert', 'chain', 'fullchain', 'privkey', 'combined', 'pkcs12', 'metadata', 'dir']", :component
    return_type 'Stdlib::Absolutepath'
  end

  def path(scope, name, component = 'fullchain')
    dir = "#{store_dir(scope)}/#{name}"
    return dir if component == 'dir'

    "#{dir}/#{Certmanager::STORE_FILENAMES.fetch(component)}"
  end

  private

  # Resolve the store location the same way the class does, so a Hiera
  # override applies to templates as well as to the resources.
  def store_dir(scope)
    call_function('lookup', {
                    'name' => 'certmanager::store_dir',
                    'value_type' => Puppet::Pops::Types::TypeFactory.string,
                    'default_value' => default_store_dir(scope),
                  })
  end

  def default_store_dir(scope)
    facts = scope['facts'] || {}
    windows = facts.dig('os', 'family') == 'windows' || facts['kernel'] == 'windows'

    windows ? 'C:/ProgramData/PuppetLabs/certmanager/certs' : '/etc/certmanager/certs'
  end
end
