# @summary Private key algorithm and size.
#
# ECDSA is the sane default in 2026. RSA is here for the load balancer that
# still hasn't been replaced.
type Certmanager::Keytype = Enum[
  'ecdsa-p256',
  'ecdsa-p384',
  'rsa-2048',
  'rsa-3072',
  'rsa-4096',
]
