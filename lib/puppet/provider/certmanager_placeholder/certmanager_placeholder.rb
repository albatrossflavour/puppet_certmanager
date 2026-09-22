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
      should = change[:should] || { ensure: 'absent' }
      current = change[:is] || get(context, [name]).first

      if should[:ensure].to_s == 'present'
        next if current[:ensure].to_s == 'present'

        context.creating(name) do
          context.notice("Writing bootstrap placeholder certificate for #{name}")
          PuppetX::Certmanager::Issuer::Selfsigned.new(name, should, config_for(should)).bootstrap
        end
      elsif current[:ensure].to_s == 'present'
        context.deleting(name) { remove(context, name) }
      end
    end
  end

  private

  # Remove a placeholder, and only a placeholder.
  #
  # By the time anyone asks for this the store may well hold the real
  # certificate the placeholder existed to make way for. Deleting that
  # because a bootstrap resource was removed from a manifest would be a
  # spectacular own goal, so the recorded backend decides.
  #
  # @param context [Puppet::ResourceApi::BaseContext]
  # @param name [String]
  # @return [void]
  def remove(context, name)
    store = PuppetX::Certmanager::Store.new(name)

    if store.metadata['backend'] == 'placeholder'
      context.notice("Removing bootstrap placeholder for #{name}")
      store.remove
    else
      context.notice("Leaving #{name} alone: a real certificate has replaced the placeholder")
    end
  end

  # @param should [Hash]
  # @return [Hash]
  def config_for(should)
    { 'validity_days' => should[:validity_days] || 30 }
  end
end
