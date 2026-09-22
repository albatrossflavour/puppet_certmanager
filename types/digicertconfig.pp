# @summary Configuration for a DigiCert CertCentral issuer instance.
#
# DigiCert is not ACME. Orders are placed against the CertCentral REST API,
# may require organisation validation, and cost money, so the backend will
# never place an order it hasn't been told to place.
#
# @param backend
#   Always `digicert` for this shape.
# @param api_key
#   CertCentral API key.
# @param organization_id
#   Numeric organisation ID the orders are placed under.
# @param product_name_id
#   CertCentral product slug, e.g. `ssl_securesite_flex`.
# @param api_url
#   Override for the CertCentral API base, for the EU endpoint or a proxy.
# @param validity_years
#   Order validity. DigiCert caps public TLS certificates at one year.
# @param auto_renew_days
#   Days before expiry at which a renewal order is placed.
# @param container_id
#   CertCentral container (sub-account) the order belongs to.
# @param signature_hash
#   Hash algorithm requested for the signature.
type Certmanager::Digicertconfig = Struct[{
    backend                   => Enum['digicert'],
    api_key                   => Certmanager::Secret,
    organization_id           => Integer[1],
    Optional[product_name_id] => String[1],
    Optional[api_url]         => Stdlib::HTTPUrl,
    Optional[validity_years]  => Integer[1, 3],
    Optional[auto_renew_days] => Integer[1, 365],
    Optional[container_id]    => Integer[1],
    Optional[signature_hash]  => Enum['sha256', 'sha384', 'sha512'],
}]
