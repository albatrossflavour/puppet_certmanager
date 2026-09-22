# frozen_string_literal: true

# certmanager collector for pdctng.
#
# Managed by Puppet through `certmanager::pdctng`. Local edits are overwritten.
#
# Certificate expiry across the estate, read from the `certmanager` fact in
# PuppetDB and exposed on pdctng's metrics endpoint.
#
# The shape of what it emits is decided almost entirely by pdctng's
# thousand-series cap, and that limit is a good constraint rather than an
# annoyance. A series per node would carry ten thousand on a real estate and
# be truncated to a tenth of an answer; a series per certificate would be
# worse, because a node with `scan_directories` pointed at /etc/pki can find
# fifty. So the estate is summarised in a fixed handful of series, and the
# only per-node detail emitted is for nodes that are actually in trouble.
#
# That set is small by definition. If it is not, the truncation is itself
# the finding, and `puppet_exporter_plugin_series_overflow` reports it.

require 'json'
require 'net/http'
require 'uri'
require 'openssl'

# Reads the `certmanager` fact out of PuppetDB and turns it into metric
# families for pdctng. Split out from the registration below so it can be
# exercised without a running daemon.
module CertmanagerCollector
  CONFIG_FILE = '/etc/puppetlabs/pdctng/certmanager.json'

  # Every certificate the fact knows about, whether or not this module
  # issued it. The scanned ones are the point: the certificate that takes a
  # service down is rarely the one in a manifest.
  QUERY = 'inventory[certname, facts.certmanager] { facts.certmanager.count > 0 }'

  module_function

  # @return [Hash] configuration written alongside this file by Puppet
  def config
    JSON.parse(File.read(CONFIG_FILE))
  rescue Errno::ENOENT, JSON::ParserError
    {}
  end

  # Ask PuppetDB for every node reporting the fact.
  #
  # Deliberately does not rescue. A PuppetDB that will not answer is a
  # collector failure, which is what `puppet_exporter_collector_consecutive_failures`
  # and the PdctngCollectorFailing alert exist for. Serving the previous
  # cycle's certificate expiry as though it were current is the one thing
  # this collector must not do.
  #
  # @param settings [Hash]
  # @return [Array<Hash>] one row per node
  def poll(settings = config)
    uri = URI.parse("#{settings.fetch('puppetdb_url', 'https://localhost:8081')}/pdb/query/v4")

    request = Net::HTTP::Post.new(uri)
    request['Content-Type'] = 'application/json'
    request.body = JSON.generate('query' => QUERY)

    response = Net::HTTP.start(uri.hostname, uri.port, http_options(settings, uri)) do |http|
      http.request(request)
    end

    raise "certmanager collector: PuppetDB returned #{response.code}: #{response.body.to_s[0, 200]}" unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  end

  # @return [Hash] Net::HTTP options, using the node's own agent certificates
  def http_options(settings, uri)
    return { use_ssl: false } unless uri.scheme == 'https'

    {
      use_ssl: true,
      cert: OpenSSL::X509::Certificate.new(File.read(settings.fetch('ssl_cert'))),
      key: OpenSSL::PKey.read(File.read(settings.fetch('ssl_key'))),
      ca_file: settings.fetch('ssl_ca'),
      verify_mode: OpenSSL::SSL::VERIFY_PEER,
      open_timeout: 10,
      read_timeout: 60,
    }
  end

  # Turn the rows into metric families.
  #
  # @param rows [Array<Hash>] whatever poll returned
  # @param context [Object, nil] pdctng's CollectorContext
  # @param settings [Hash]
  # @return [Array<PDCTNG::MetricFamily>]
  def families(rows, context = nil, settings = config)
    return [] if rows.nil? || rows.empty?

    nodes = rows.filter_map { |row| node_summary(row) }
    return [] if nodes.empty?

    estate(nodes) + attention(nodes, context, settings)
  end

  # @return [Hash, nil]
  def node_summary(row)
    fact = row['facts.certmanager']
    return nil unless fact.is_a?(Hash)

    {
      certname: row['certname'],
      total: fact['count'].to_i,
      managed: fact['managed_count'].to_i,
      expired: Array(fact['expired']).length,
      critical: Array(fact['expiring_critical']).length,
      soon: Array(fact['expiring_soon']).length,
      placeholders: Array(fact['placeholders']).length,
      soonest: fact['soonest_expiry'],
      stale: !Hash(fact['warnings']).empty?,
    }
  end

  # The fixed part: a handful of series that describe the whole estate and
  # do not grow with it.
  #
  # @return [Array<PDCTNG::MetricFamily>]
  def estate(nodes)
    managed = nodes.sum { |n| n[:managed] }
    total = nodes.sum { |n| n[:total] }

    [
      gauge('certmanager_nodes_reporting_total',
            'Nodes reporting the certmanager fact',
            [sample(nodes.length)]),
      gauge('certmanager_certificates_total',
            'Certificates known to certmanager across the estate, by whether it issued them',
            [sample(managed, 'managed' => 'true'), sample(total - managed, 'managed' => 'false')]),
      gauge('certmanager_nodes_total',
            'Nodes by the worst state any of their certificates is in',
            estate_states(nodes)),
    ]
  end

  # One series per state rather than per node, and a node counted once
  # under its worst state. A node with an expired certificate and another
  # expiring next week is an expired node; counting it twice makes the
  # states sum to more than the fleet and no panel recovers from that.
  #
  # @return [Array<PDCTNG::MetricFamily::Sample>]
  def estate_states(nodes)
    counts = Hash.new(0)

    nodes.each do |node|
      counts[worst_state(node)] += 1
    end

    ['expired', 'critical', 'soon', 'placeholder', 'stale', 'ok'].map do |state|
      sample(counts[state], 'state' => state)
    end
  end

  # @return [String]
  def worst_state(node)
    return 'expired' if node[:expired].positive?
    return 'critical' if node[:critical].positive?
    return 'placeholder' if node[:placeholders].positive?
    return 'soon' if node[:soon].positive?
    return 'stale' if node[:stale]

    'ok'
  end

  # The variable part, and the only thing here that scales with the fleet.
  #
  # Restricted to nodes that need looking at, because a series for every
  # healthy node is both useless and the fastest route to the cap. A node
  # whose soonest expiry is comfortably away contributes to the counts above
  # and nothing else.
  #
  # @return [Array<PDCTNG::MetricFamily>]
  def attention(nodes, context, settings)
    threshold = settings.fetch('detail_within_days', 30).to_i

    wanted = nodes.select { |node| needs_attention?(node, threshold) }
                  .sort_by { |node| node[:soonest] || -1 }
    return [] if wanted.empty?

    samples = wanted.filter_map do |node|
      next if node[:soonest].nil?

      sample(node[:soonest], labels_for(node, context))
    end

    return [] if samples.empty?

    [
      gauge('certmanager_node_soonest_expiry_days',
            'Days until the soonest certificate expiry, for nodes at or inside the detail threshold',
            samples),
    ]
  end

  # @return [Boolean]
  def needs_attention?(node, threshold)
    return true if node[:expired].positive? || node[:placeholders].positive? || node[:stale]
    return false if node[:soonest].nil?

    node[:soonest] <= threshold
  end

  # @return [Hash]
  def labels_for(node, context)
    labels = { 'node' => node[:certname] }
    return labels unless context

    labels['environment'] = context.environment_for(node[:certname])
    labels.merge(context.filter_labels_for(node[:certname]) || {})
  rescue StandardError
    # A context that cannot answer is not a reason to lose the metric.
    labels
  end

  # @return [PDCTNG::MetricFamily]
  def gauge(name, help, samples)
    PDCTNG::MetricFamily.new(name: name, type: 'gauge', help: help, samples: samples)
  end

  # @return [PDCTNG::MetricFamily::Sample]
  def sample(value, labels = {})
    PDCTNG::MetricFamily::Sample.new(value: value, labels: labels)
  end
end

# Guarded so the file can be required by its own specs without a daemon.
if defined?(PDCTNG::PluginLoader)
  PDCTNG::PluginLoader.register(
    name: 'certmanager',
    contract_version: 1,
    # Evaluated every cycle, so removing the config file switches the collector
    # off rather than leaving it failing.
    enabled: -> { File.exist?(CertmanagerCollector::CONFIG_FILE) },
    timeout: 60,
    # Both delegate, so the brace form is safe here. Anything that grows a
    # `rescue` has to become `lambda do ... end`: a brace-delimited lambda
    # cannot carry one, and pdctng's loader swallows the SyntaxError, so the
    # collector silently is not there and the daemon looks perfectly healthy.
    poll: -> { CertmanagerCollector.poll },
    families: ->(data, ctx) { CertmanagerCollector.families(data, ctx) },
  )
end
