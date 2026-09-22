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
#
# @param config_dir
#   certbot's configuration directory, where it keeps account state and its
#   own `live` and `renewal-hooks` trees. Only worth setting if you run
#   certbot somewhere other than `/etc/letsencrypt`.
#
# @param certbot_path
#   Path to certbot for this issuer specifically. Normally comes from
#   `certmanager::certbot_path` and does not need setting here.
#
# @param wacs_path
#   Path to wacs.exe for this issuer specifically. Normally comes from
#   `certmanager::wacs_path`.
#
# @param environment
#   Extra environment variables for the ACME client. certbot takes several
#   of its settings this way and there is no flag for them: `HTTPS_PROXY`
#   for a host that reaches the internet through a proxy, and
#   `REQUESTS_CA_BUNDLE` when the ACME endpoint is signed by a CA the
#   system does not already trust.
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
    Optional[config_dir]              => Stdlib::Absolutepath,
    Optional[certbot_path]            => String[1],
    Optional[wacs_path]               => String[1],
    Optional[environment]             => Hash[String[1], String],
}]
