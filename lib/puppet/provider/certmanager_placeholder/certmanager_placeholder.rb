# frozen_string_literal: true

require_relative '../../../puppet_x/certmanager/issuer/selfsigned'
require_relative '../../../puppet_x/certmanager/store'

# Provider for certmanager_placeholder.
class Puppet::Provider::CertmanagerPlaceholder::CertmanagerPlaceholder
  # A placeholder is "present" whenever anything at all is in the store, real
  # certificate included. That is the whole safety property: once a real
  # certificate exists there is nothing for this resource to do, ever.
  #
  # @param _context [Puppet::ResourceApi::BaseContext]
  # @param names [Array<String>, nil]
  # @return [Array<Hash>]
  def get(_context, names = nil)
    Array(names).map do |name|
      {
        name: name,
        ensure: PuppetX::Certmanager::Store.new(name).exist? ? 'present' : 'absent',
      }
    end
  end

  # @param context [Puppet::ResourceApi::BaseContext]
  # @param changes [Hash]
  # @return [void]
  def set(context, changes)
    changes.each do |name, change|
      should = change[:should]
      next if should.nil? || should[:ensure].to_s != 'present'
      next if (change[:is] || get(context, [name]).first)[:ensure].to_s == 'present'

      context.creating(name) do
        context.notice("Writing bootstrap placeholder certificate for #{name}")
        PuppetX::Certmanager::Issuer::Selfsigned.new(name, should, config_for(should)).bootstrap
      end
    end
  end

  private

  # @param should [Hash]
  # @return [Hash]
  def config_for(should)
    { 'validity_days' => should[:validity_days] || 30 }
  end
end
