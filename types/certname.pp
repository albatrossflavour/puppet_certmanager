# @summary A certificate name.
#
# Usually an FQDN, but it is only an identifier: the actual names on the
# certificate come from `common_name` and `san`. Constrained to characters
# that are safe as a directory name on both POSIX and Windows.
type Certmanager::Certname = Pattern[/\A[a-zA-Z0-9][a-zA-Z0-9._*-]{0,252}\z/]
