# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/certmanager/paths'
require 'puppet_x/certmanager/inventory'

describe 'certmanager fact', :store do
  subject(:fact) { Facter.fact(:certmanager).value }

  before(:each) do
    Facter.clear
    allow(Facter.fact(:kernel)).to receive(:value).and_return('Linux') if Facter.fact(:kernel)
  end

  after(:each) { Facter.clear }

  def write_cache(contents)
    path = PuppetX::Certmanager::Paths.cache_file
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.generate(contents))
  end

  let(:cached) do
    {
      'certificates' => {
        'www.example.com' => { 'days_left' => 40, 'expired' => false, 'managed' => true },
      },
      'count' => 1,
      'managed_count' => 1,
      'expired' => [],
      'expiring_critical' => [],
      'expiring_soon' => [],
      'placeholders' => [],
      'soonest_expiry' => 40,
      'generated_at' => Time.now.utc.iso8601,
    }
  end

  # The cache is rebuilt when a certificate is issued, which in a Puppet run
  # happens before the consumers that use it are declared. Taking the
  # consumer list from the cache means it is wrong until the next scheduled
  # refresh.
  it 'reads consumers live rather than trusting the cache' do
    write_cache(cached)
    hooks = File.join(PuppetX::Certmanager::Paths.hook_dir, 'www.example.com')
    FileUtils.mkdir_p(hooks)
    FileUtils.touch(File.join(hooks, 'nginx-www.sh'))

    expect(fact['certificates']['www.example.com']['consumers']).to eq(['nginx-www.sh'])
  end

  it 'reports what the cache says' do
    write_cache(cached)

    expect(fact['count']).to eq(1)
    expect(fact['certificates']).to have_key('www.example.com')
    expect(fact['warnings']).to be_empty
  end

  # A fact that quietly reports zero certificates when its cache is missing
  # is worse than one that reports nothing at all: it looks like good news.
  it 'says so when there is no cache rather than reporting an empty estate as fact' do
    expect(fact['count']).to eq(0)
    expect(fact['warnings']).to have_key('cache')
  end

  it 'flags a stale cache, because expiry data that old is probably wrong' do
    write_cache(cached.merge('generated_at' => (Time.now.utc - (48 * 3600)).iso8601))

    expect(fact['warnings']['cache_stale']).to match(%r{48 hours ago})
  end

  it 'survives a cache that has been truncated or corrupted' do
    path = PuppetX::Certmanager::Paths.cache_file
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, '{"certificates": {"www')

    expect(fact['count']).to eq(0)
    expect(fact['warnings']).to have_key('cache')
  end
end
