# frozen_string_literal: true

require_relative '../../../puppet_x/certmanager/inventory'
require_relative '../../../puppet_x/certmanager/issuer'
require_relative '../../../puppet_x/certmanager/paths'
require_relative '../../../puppet_x/certmanager/store'

# Provider for certmanager_certificate.
#
# Reads state from the canonical store, which every backend writes to, so
# there is exactly one place that answers "what certificate is actually on
# this host". Writes are delegated to the issuer backend named by the
# resource.
#
# Deliberately not built on SimpleProvider. SimpleProvider's `delete` is
# handed only the resource name, and revoking a certificate needs the
# issuer's credentials, which live in the desired state.
class Puppet::Provider::CertmanagerCertificate::CertmanagerCertificate
  # @param _context [Puppet::ResourceApi::BaseContext]
  # @param names [Array<String>, nil] restricted set, thanks to simple_get_filter
  # @return [Array<Hash>]
  def get(_context, names = nil)
    (names || discover).uniq.map { |name| read(name) }
  end

  # @param context [Puppet::ResourceApi::BaseContext]
  # @param changes [Hash]
  # @return [void]
  def set(context, changes)
    changes.each do |name, change|
      current = change[:is] || read(name)
      should = change[:should] || { name: name, ensure: 'absent' }

      if current[:ensure].to_s == 'absent' && should[:ensure].to_s == 'present'
        context.creating(name) { create(context, name, should) }
      elsif current[:ensure].to_s == 'present' && should[:ensure].to_s == 'absent'
        context.deleting(name) { delete(context, name, should) }
      elsif current[:ensure].to_s == 'present'
        context.updating(name) { update(context, name, should, current) }
      end
    end
  end

  # Sort and deduplicate the SAN list so a manifest listing names in a
  # different order from the certificate isn't reported as drift on every
  # run.
  #
  # @param _context [Puppet::ResourceApi::BaseContext]
  # @param resources [Array<Hash>]
  # @return [Array<Hash>]
  def canonicalize(_context, resources)
    resources.map do |resource|
      resource[:san] = Array(resource[:san]).compact.uniq.sort if resource.key?(:san)
      resource
    end
  end

  private

  # @return [void]
  def create(context, name, should)
    context.notice("Issuing certificate #{name} with issuer '#{should[:issuer]}'")
    issue(context, name, should)
  end

  # @return [void]
  def update(context, name, should, current)
    reasons = PuppetX::Certmanager::Issuer.for(name, should).drift
    reasons = ["state is #{current[:certificate_state]}"] if reasons.empty?

    context.notice("Renewing certificate #{name}: #{reasons.join(', ')}")
    issue(context, name, should)
  end

  # Removing a certificate is two separate decisions: tell the CA the
  # certificate is dead, and delete the key material. They are not the same
  # thing and conflating them loses data, so deletion is opt-in through
  # `purge_on_absent`.
  #
  # @return [void]
  def delete(context, name, should)
    begin
      PuppetX::Certmanager::Issuer.for(name, should).revoke
    rescue PuppetX::Certmanager::Issuer::Base::Error => e
      context.warning("Could not revoke #{name} with the CA: #{e.message}")
    end

    if should[:purge_on_absent]
      context.notice("Removing certificate #{name} from the store")
      PuppetX::Certmanager::Store.new(name).remove
    else
      context.notice("Revoked #{name}; files left in the store (set purge_on_absent to delete them)")
    end
  end

  # @return [void]
  def issue(context, name, should)
    PuppetX::Certmanager::Issuer.for(name, should).issue
    refresh_cache(context)
  rescue PuppetX::Certmanager::Issuer::Base::Error => e
    context.err(e.message)
    raise Puppet::Error, e.message
  end

  # Rebuild the fact cache straight after a change. Issuance is exactly the
  # moment the cached expiry date becomes wrong, and waiting for the
  # scheduled refresh means the next Puppet run reports stale data about a
  # certificate this run just replaced.
  #
  # Best effort: a cache that failed to write is a reporting problem, not a
  # reason to fail a certificate that was issued successfully.
  #
  # @return [void]
  def refresh_cache(context)
    PuppetX::Certmanager::Inventory.write_cache(PuppetX::Certmanager::Inventory.build)
  rescue StandardError => e
    context.warning("Certificate issued, but the fact cache could not be rebuilt: #{e.message}")
  end

  # Certificate names present in the store.
  #
  # @return [Array<String>]
  def discover
    root = PuppetX::Certmanager::Paths.store_dir
    return [] unless File.directory?(root)

    Dir.children(root).select { |child| File.file?(File.join(root, child, 'cert.pem')) }
  end

  # Read one certificate's state out of the store.
  #
  # @param name [String]
  # @return [Hash]
  def read(name)
    store = PuppetX::Certmanager::Store.new(name)
    return absent(name) unless store.exist?

    info = store.info
    return absent(name).merge(ensure: 'present', certificate_state: 'unreadable') if info.nil?

    {
      name: name,
      ensure: 'present',
      certificate_state: state_of(info, store.metadata),
      san: info['san'],
      key_type: info['key_type'],
      not_after: info['not_after'],
      days_left: info['days_left'],
      serial: info['serial'],
      fingerprint_sha256: info['fingerprint_sha256'],
    }
  end

  # @param info [Hash] parsed certificate
  # @param metadata [Hash] what the module recorded when it deployed it
  # @return [String]
  def state_of(info, metadata)
    backend = metadata['backend']
    return 'placeholder' if backend == 'placeholder' || (info['self_signed'] && backend && backend != 'selfsigned')
    return 'renewal_due' if info['days_left'] <= (metadata['renew_before_days'] || 30)

    'current'
  end

  # @param name [String]
  # @return [Hash]
  def absent(name)
    {
      name: name,
      ensure: 'absent',
      certificate_state: 'missing',
      san: [],
      key_type: 'ecdsa-p256',
      not_after: nil,
      days_left: nil,
      serial: nil,
      fingerprint_sha256: nil,
    }
  end
end
