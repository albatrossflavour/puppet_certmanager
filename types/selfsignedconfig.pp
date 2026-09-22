# @summary Configuration for a self-signed issuer instance.
#
# For labs, for internal services nobody outside can reach, and for the
# bootstrap placeholder that breaks the first-run deadlock.
#
# @param backend
#   Always `selfsigned` for this shape.
# @param validity_days
#   How long the generated certificate is good for.
# @param subject
#   Default subject components (O, OU, C, ST, L) merged into every
#   certificate this issuer signs.
type Certmanager::Selfsignedconfig = Struct[{
    backend                 => Enum['selfsigned'],
    Optional[validity_days] => Integer[1, 3650],
    Optional[subject]       => Hash[Enum['O', 'OU', 'C', 'ST', 'L'], String[1]],
}]
