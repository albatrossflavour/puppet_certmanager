# frozen_string_literal: true

# The `certmanager` fact.
#
# Reads the cache written by the refresh task rather than parsing every
# certificate on the host on every Puppet run. A host with a few hundred
# certificates in its scan directories would otherwise add seconds to each
# run, and the data changes on a scale of days, not minutes.
#
# The cache being stale is itself worth knowing, so that shows up as a
# warning in the fact rather than being papered over.
Facter.add(:certmanager, type: :aggregate) do
  confine { ['Linux', 'windows', 'SunOS', 'FreeBSD'].include?(Facter.value(:kernel)) }

  require 'json'
  require 'time'

  # Under a Puppet run pluginsync has already put the module's lib/ on the
  # load path, so the plain require works. Run standalone (facter
  # --custom-dir, or a Bolt task), it hasn't, so fall back to a path
  # relative to this file.
  begin
    require 'puppet_x/certmanager/paths'
    require 'puppet_x/certmanager/inventory'
  rescue LoadError
    begin
      libdir = File.expand_path('..', File.dirname(File.absolute_path(__FILE__)))
      require File.join(libdir, 'puppet_x', 'certmanager', 'paths')
      require File.join(libdir, 'puppet_x', 'certmanager', 'inventory')
    rescue LoadError => e
      Facter.debug("certmanager fact could not load its libraries: #{e.message}")
    end
  end

  cache_path = defined?(PuppetX::Certmanager::Paths) ? PuppetX::Certmanager::Paths.cache_file : nil

  cached = begin
    (cache_path && File.file?(cache_path)) ? JSON.parse(File.read(cache_path)) : nil
  rescue JSON::ParserError, SystemCallError, IOError
    nil
  end

  chunk(:certificates) do
    { 'certificates' => cached ? cached.fetch('certificates', {}) : {} }
  end

  chunk(:summary) do
    if cached
      cached.except('certificates')
    else
      {
        'count' => 0,
        'managed_count' => 0,
        'expired' => [],
        'expiring_critical' => [],
        'expiring_soon' => [],
        'placeholders' => [],
        'soonest_expiry' => nil,
        'generated_at' => nil,
      }
    end
  end

  chunk(:warnings) do
    warnings = {}

    if cache_path.nil?
      warnings['libraries'] = 'certmanager libraries could not be loaded; pluginsync may not have run'
    elsif cached.nil?
      warnings['cache'] = "no usable cache at #{cache_path}; run the certmanager::refresh_facts task"
    else
      max_age = 24 * 3600
      generated = begin
        Time.parse(cached['generated_at'].to_s)
      rescue ArgumentError, TypeError
        nil
      end

      if generated.nil?
        warnings['cache_time'] = 'cache has no usable timestamp'
      elsif (Time.now - generated) > max_age
        hours = ((Time.now - generated) / 3600).round
        warnings['cache_stale'] = "cache last built #{hours} hours ago; expiry data may be wrong"
      end
    end

    { 'warnings' => warnings }
  end
end
