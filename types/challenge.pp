# @summary ACME challenge type.
#
# `dns-01` is the only one that works for wildcards, and the only one that
# doesn't need the host to be reachable from the internet.
type Certmanager::Challenge = Enum['http-01', 'dns-01', 'tls-alpn-01']
