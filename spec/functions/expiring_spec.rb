# frozen_string_literal: true

require 'spec_helper'

describe 'certmanager::expiring' do
  let(:facts) do
    {
      certmanager: {
        'certificates' => {
          'soon.example.com' => { 'days_left' => 5, 'expired' => false },
          'later.example.com' => { 'days_left' => 60, 'expired' => false },
          'gone.example.com' => { 'days_left' => -3, 'expired' => true },
        },
      },
    }
  end

  it 'reports the soonest first, so the list reads as a work queue' do
    expect(subject).to run.with_params(30).and_return(['gone.example.com', 'soon.example.com'])
  end

  it 'leaves out anything comfortably in date' do
    expect(subject).to run.with_params(10).and_return(['gone.example.com', 'soon.example.com'])
  end

  it 'widens to everything when asked for a long enough window' do
    expect(subject).to run.with_params(90)
                          .and_return(['gone.example.com', 'soon.example.com', 'later.example.com'])
  end

  it 'defaults to thirty days' do
    expect(subject).to run.with_params.and_return(['gone.example.com', 'soon.example.com'])
  end

  context 'without a certmanager fact yet' do
    let(:facts) { {} }

    it 'returns nothing rather than failing the run' do
      expect(subject).to run.with_params(30).and_return([])
    end
  end
end
