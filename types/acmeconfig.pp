# @summary Configuration for an ACME issuer instance (certbot or win-acme).
#
# @param backend
#   Always `acme` for this shape.
# @param directory_url
#   The ACME directory endpoint. Let's Encrypt production and staging,
#   ZeroSSL, Buypass and DigiCert's own ACME service all work here.
# @param email
#   Contact address registered with the CA. Expiry warnings go here.
# @param challenge
#   Default challenge type for certificates issued by this issuer.
# @param dns_plugin
#   certbot DNS plugin name (`cloudflare`, `route53`, `rfc2136`, ...) when
#   `challenge` is `dns-01`. Ignored otherwise.
# @param dns_credentials
#   Credential file contents for the DNS plugin. Written 0600.
# @param dns_propagation_seconds
#   How long to wait for the DNS record to propagate before asking the CA to
#   validate. Too low is the single most common cause of dns-01 failures.
# @param webroot
#   Document root for `http-01` when the web server is already running.
#   Omit to let the backend stand up its own listener.
# @param eab_kid
#   External Account Binding key identifier, required by ZeroSSL, DigiCert
#   ACME and most commercial ACME endpoints.
# @param eab_hmac_key
#   External Account Binding HMAC key.
# @param server_port
#   Port for the standalone challenge listener.
# @param preferred_chain
#   Issuer common name of the preferred chain, when the CA offers more than
#   one (the ISRG X1 / DST Root cross-sign problem).
type Certmanager::Acmeconfig = Struct[{
    backend                           => Enum['acme'],
    directory_url                     => String[1],
    email                             => Optional[String[1]],
    Optional[challenge]               => Certmanager::Challenge,
    Optional[dns_plugin]              => String[1],
    Optional[dns_credentials]         => Certmanager::Secret,
    Optional[dns_propagation_seconds] => Integer[0, 3600],
    Optional[webroot]                 => Stdlib::Absolutepath,
    Optional[eab_kid]                 => String[1],
    Optional[eab_hmac_key]            => Certmanager::Secret,
    Optional[server_port]             => Stdlib::Port,
    Optional[preferred_chain]         => String[1],
}]
