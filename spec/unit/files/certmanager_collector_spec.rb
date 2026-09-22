# frozen_string_literal: true

require 'spec_helper'

# The daemon supplies these. Defined here so the collector can be exercised
# without one, which is the whole reason the registration at the bottom of
# the file is guarded.
module PDCTNG; end

class PDCTNG::MetricFamily
  class Sample
    attr_reader :value, :labels

    def initialize(value:, labels: {})
      @value = value
      @labels = labels
    end
  end

  attr_reader :name, :type, :help, :samples

  def initialize(name:, type:, help:, samples:)
    @name = name
    @type = type
    @help = help
    @samples = samples
  end
end

# The two methods the collector asks of pdctng's context. Declared so the
# doubles below verify against something rather than accepting any message.
class PDCTNG::CollectorContext
  def environment_for(_certname); end
  def filter_labels_for(_certname); end
end

require_relative '../../../files/pdctng/certmanager'

describe CertmanagerCollector do
  subject(:collector) { described_class }

  def node(certname, **overrides)
    fact = {
      'count' => 3,
      'managed_count' => 1,
      'expired' => [],
      'expiring_critical' => [],
      'expiring_soon' => [],
      'placeholders' => [],
      'soonest_expiry' => 200,
      'warnings' => {},
    }.merge(overrides.transform_keys(&:to_s))

    { 'certname' => certname, 'facts.certmanager' => fact }
  end

  def family(families, name)
    families.find { |f| f.name == name }
  end

  def value_for(fam, labels)
    fam.samples.find { |s| s.labels == labels }&.value
  end

  let(:settings) { { 'detail_within_days' => 30 } }

  describe '.families' do
    it 'emits nothing when no node reports the fact' do
      expect(collector.families([], nil, settings)).to eq([])
    end

    it 'emits nothing rather than raising when the poll failed and left nil' do
      expect(collector.families(nil, nil, settings)).to eq([])
    end

    it 'ignores a row whose fact is not the shape it expects' do
      rows = [{ 'certname' => 'broken.example.com', 'facts.certmanager' => 'not a hash' }]

      expect(collector.families(rows, nil, settings)).to eq([])
    end

    it 'counts the nodes reporting' do
      families = collector.families([node('a'), node('b')], nil, settings)

      expect(family(families, 'certmanager_nodes_reporting_total').samples.first.value).to eq(2)
    end

    it 'separates what this module issued from what it merely found' do
      families = collector.families([node('a'), node('b')], nil, settings)
      fam = family(families, 'certmanager_certificates_total')

      expect(value_for(fam, 'managed' => 'true')).to eq(2)
      expect(value_for(fam, 'managed' => 'false')).to eq(4)
    end
  end

  describe 'the estate state counts' do
    # A node counted under two states makes the states sum to more than the
    # fleet, and no panel recovers from that.
    it 'counts a node once, under the worst state it is in' do
      rows = [node('a', expired: ['x'], expiring_soon: ['y', 'z'], placeholders: ['p'])]
      fam = family(collector.families(rows, nil, settings), 'certmanager_nodes_total')

      expect(value_for(fam, 'state' => 'expired')).to eq(1)
      expect(value_for(fam, 'state' => 'soon')).to eq(0)
      expect(value_for(fam, 'state' => 'placeholder')).to eq(0)
    end

    it 'ranks critical above a placeholder, and a placeholder above merely soon' do
      rows = [
        node('a', expiring_critical: ['x'], placeholders: ['p']),
        node('b', placeholders: ['p'], expiring_soon: ['y']),
        node('c', expiring_soon: ['y']),
      ]
      fam = family(collector.families(rows, nil, settings), 'certmanager_nodes_total')

      expect(value_for(fam, 'state' => 'critical')).to eq(1)
      expect(value_for(fam, 'state' => 'placeholder')).to eq(1)
      expect(value_for(fam, 'state' => 'soon')).to eq(1)
    end

    # A fact nobody has refreshed is reporting yesterday's expiry dates, and
    # a node quietly doing that is worth seeing.
    it 'counts a node whose fact cache went stale' do
      rows = [node('a', warnings: { 'cache_stale' => 'cache last built 48 hours ago' })]
      fam = family(collector.families(rows, nil, settings), 'certmanager_nodes_total')

      expect(value_for(fam, 'state' => 'stale')).to eq(1)
    end

    it 'emits a zero for a state nothing is in, so a panel has something to read against' do
      fam = family(collector.families([node('a')], nil, settings), 'certmanager_nodes_total')

      expect(value_for(fam, 'state' => 'expired')).to eq(0)
      expect(value_for(fam, 'state' => 'ok')).to eq(1)
    end
  end

  describe 'the per-node detail' do
    # This is the only family that grows with the fleet, and pdctng drops a
    # plugin's samples past a thousand series. A healthy node contributes to
    # the counts and nothing else.
    it 'leaves out nodes that are comfortably in date' do
      expect(family(collector.families([node('a', soonest_expiry: 200)], nil, settings),
                    'certmanager_node_soonest_expiry_days')).to be_nil
    end

    it 'includes a node inside the threshold' do
      fam = family(collector.families([node('a', soonest_expiry: 12)], nil, settings),
                   'certmanager_node_soonest_expiry_days')

      expect(value_for(fam, 'node' => 'a')).to eq(12)
    end

    it 'honours a threshold the site widened' do
      rows = [node('a', soonest_expiry: 45)]

      expect(family(collector.families(rows, nil, settings), 'certmanager_node_soonest_expiry_days')).to be_nil
      expect(family(collector.families(rows, nil, 'detail_within_days' => 60),
                    'certmanager_node_soonest_expiry_days')).not_to be_nil
    end

    it 'includes a node with an expired certificate however far off the next one is' do
      fam = family(collector.families([node('a', expired: ['x'], soonest_expiry: 300)], nil, settings),
                   'certmanager_node_soonest_expiry_days')

      expect(value_for(fam, 'node' => 'a')).to eq(300)
    end

    it 'includes a node still running on a bootstrap placeholder' do
      fam = family(collector.families([node('a', placeholders: ['x'], soonest_expiry: 300)], nil, settings),
                   'certmanager_node_soonest_expiry_days')

      expect(fam).not_to be_nil
    end

    it 'puts the soonest first, so truncation at the cap keeps what matters' do
      rows = [node('a', soonest_expiry: 20), node('b', soonest_expiry: 2), node('c', soonest_expiry: 9)]
      fam = family(collector.families(rows, nil, settings), 'certmanager_node_soonest_expiry_days')

      expect(fam.samples.map(&:value)).to eq([2, 9, 20])
    end

    it 'leaves the family out entirely when no node has a usable expiry' do
      rows = [node('a', expired: ['x'], soonest_expiry: nil)]

      expect(family(collector.families(rows, nil, settings), 'certmanager_node_soonest_expiry_days')).to be_nil
    end
  end

  describe 'labels' do
    let(:context) do
      instance_double(PDCTNG::CollectorContext,
                      environment_for: 'production',
                      filter_labels_for: { 'datacenter' => 'lab' })
    end

    it 'carries the environment and the site filter labels' do
      fam = family(collector.families([node('a', soonest_expiry: 5)], context, settings),
                   'certmanager_node_soonest_expiry_days')

      expect(fam.samples.first.labels).to eq('node' => 'a', 'environment' => 'production', 'datacenter' => 'lab')
    end

    # Losing the metric because the daemon could not answer a question about
    # labels would be a poor trade.
    it 'still emits the sample when the context cannot answer' do
      broken = instance_double(PDCTNG::CollectorContext)
      allow(broken).to receive(:environment_for).and_raise(StandardError)

      fam = family(collector.families([node('a', soonest_expiry: 5)], broken, settings),
                   'certmanager_node_soonest_expiry_days')

      expect(fam.samples.first.labels).to eq('node' => 'a')
    end
  end

  describe '.config' do
    it 'comes back empty when the file is not there, which is how the collector switches off' do
      stub_const("#{described_class}::CONFIG_FILE", '/nonexistent/certmanager.json')

      expect(collector.config).to eq({})
    end
  end

  describe '.poll' do
    # Plain HTTP so http_options runs for real rather than being stubbed
    # out. The TLS branch is covered separately, below.
    let(:settings) { { 'puppetdb_url' => 'http://puppetdb.example.com:8080' } }

    def http_response(code, body)
      klass = (code == 200) ? Net::HTTPOK : Net::HTTPBadRequest
      instance_double(klass, code: code.to_s, body: body).tap do |double|
        allow(double).to receive(:is_a?).with(Net::HTTPSuccess).and_return(code == 200)
      end
    end

    it 'asks PuppetDB for every node reporting the fact' do
      sent = nil
      allow(Net::HTTP).to receive(:start) do |*_args, &block|
        http = instance_double(Net::HTTP)
        allow(http).to receive(:request) { |req| sent = req.body }
        block.call(http)
        http_response(200, '[]')
      end

      collector.poll(settings)

      expect(JSON.parse(sent)['query']).to include('facts.certmanager')
    end

    # Serving last cycle's expiry dates as though they were current is the
    # one thing this collector must not do, so a bad response is a collector
    # failure rather than a quiet empty family.
    it 'raises rather than reporting stale data when PuppetDB will not answer' do
      allow(Net::HTTP).to receive(:start).and_return(http_response(503, 'service unavailable'))

      expect { collector.poll(settings) }.to raise_error(%r{PuppetDB returned 503})
    end
  end

  describe '.http_options' do
    it 'does not reach for certificates on a plain HTTP endpoint' do
      expect(collector.http_options({}, URI.parse('http://puppetdb.example.com:8080')))
        .to eq(use_ssl: false)
    end

    # PE already trusts the node's own agent certificate, which is why that
    # is the default rather than something a site has to mint.
    it 'presents the agent certificate and verifies the peer over TLS' do
      cert, key = CertmanagerSpec.certificate(common_name: 'puppet.example.com')
      dir = Dir.mktmpdir('pdb-ssl')
      File.write(File.join(dir, 'cert.pem'), cert.to_pem)
      File.write(File.join(dir, 'key.pem'), key.to_pem)

      options = collector.http_options(
        { 'ssl_cert' => File.join(dir, 'cert.pem'),
          'ssl_key' => File.join(dir, 'key.pem'),
          'ssl_ca' => '/ca.pem' },
        URI.parse('https://puppetdb.example.com:8081'),
      )

      expect(options).to include(use_ssl: true, ca_file: '/ca.pem', verify_mode: OpenSSL::SSL::VERIFY_PEER)
      expect(options[:cert]).to be_a(OpenSSL::X509::Certificate)
    ensure
      FileUtils.rm_rf(dir)
    end
  end
end
