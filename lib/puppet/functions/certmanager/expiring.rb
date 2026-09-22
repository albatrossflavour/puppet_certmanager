# frozen_string_literal: true

# Certificates on this node expiring within the given number of days.
#
# Reads the `certmanager` fact, so it reports on everything the inventory
# knows about, not only what this catalog declares. That distinction is the
# point: the certificate about to expire is usually the one nobody put in
# Puppet.
#
# @example Fail a run when something is about to break
#   $doomed = certmanager::expiring(7)
#   unless empty($doomed) {
#     notify { "certificates expiring within 7 days: ${join($doomed, ', ')}": }
#   }
Puppet::Functions.create_function(:'certmanager::expiring', Puppet::Functions::InternalFunction) do
  # Already-expired certificates are included: `days_left` goes negative
  # once a certificate expires, so it is inside any window you ask about,
  # and a certificate that expired last week is not less urgent than one
  # expiring next week.
  #
  # @param days How far ahead to look.
  # @return [Array[String]] Certificate names, soonest first.
  dispatch :expiring do
    scope_param
    optional_param 'Integer[0]', :days
    return_type 'Array[String]'
  end

  def expiring(scope, days = 30)
    certificates = (scope['facts'] || {}).dig('certmanager', 'certificates') || {}

    certificates.select { |_, cert| cert['days_left'].to_i <= days }
                .sort_by { |_, cert| cert['days_left'].to_i }
                .map(&:first)
  end
end
