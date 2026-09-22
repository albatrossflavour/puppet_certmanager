# @summary The canonical file locations for one certificate.
#
# Every issuer lands its output here, so consuming configuration never has to
# know which CA signed the certificate.
#
# @param dir
#   The certificate's directory in the store.
# @param cert
#   Leaf certificate, PEM.
# @param chain
#   Intermediate chain without the leaf, PEM. Some servers want this
#   separately (nginx does not, Apache's SSLCertificateChainFile did).
# @param fullchain
#   Leaf plus intermediates, PEM. This is what nginx and haproxy want.
# @param privkey
#   Private key, PEM, mode 0600.
# @param combined
#   Private key plus full chain in one file, for haproxy and dovecot.
# @param pkcs12
#   PKCS#12 bundle, for Java keystores and Windows.
# @param metadata
#   JSON sidecar recording issuer, serial, fingerprints and issuance time.
type Certmanager::Paths = Struct[{
    dir       => Stdlib::Absolutepath,
    cert      => Stdlib::Absolutepath,
    chain     => Stdlib::Absolutepath,
    fullchain => Stdlib::Absolutepath,
    privkey   => Stdlib::Absolutepath,
    combined  => Stdlib::Absolutepath,
    pkcs12    => Stdlib::Absolutepath,
    metadata  => Stdlib::Absolutepath,
}]
