# @summary One certificate's entry in the `certmanager` fact.
#
# @param path
#   Absolute path to the certificate this entry describes.
# @param managed
#   True when this module issued and owns the certificate. False for
#   certificates found by the directory scan.
# @param issuer
#   Name of the issuer instance that produced it, or `unknown` for scanned
#   certificates whose origin can't be determined.
# @param self_signed
#   True for a self-signed certificate. On a managed certificate this almost
#   always means the bootstrap placeholder is still in place and real
#   issuance has not succeeded yet.
# @param subject
#   Certificate subject, RFC 2253 form.
# @param issuer_dn
#   Issuing CA's distinguished name.
# @param serial
#   Serial number, hex.
# @param san
#   Subject alternative names.
# @param not_before
#   Start of the validity window, ISO 8601 UTC.
# @param not_after
#   End of the validity window, ISO 8601 UTC.
# @param days_left
#   Whole days until expiry. Negative once expired.
# @param expired
#   True when `not_after` is in the past.
# @param key_type
#   Public key algorithm and size.
# @param signature_algorithm
#   Algorithm the CA signed with.
# @param fingerprint_sha256
#   SHA-256 fingerprint of the DER encoding, colon-separated hex.
# @param consumers
#   Services registered against this certificate through
#   `certmanager::consumer`.
type Certmanager::Certinfo = Struct[{
    path                          => Stdlib::Absolutepath,
    managed                       => Boolean,
    issuer                        => String[1],
    self_signed                   => Boolean,
    subject                       => String,
    issuer_dn                     => String,
    serial                        => String,
    san                           => Array[String],
    not_before                    => String,
    not_after                     => String,
    days_left                     => Integer,
    expired                       => Boolean,
    key_type                      => String,
    signature_algorithm           => String,
    fingerprint_sha256            => String,
    Optional[consumers]           => Array[String],
}]
