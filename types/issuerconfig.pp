# @summary Any issuer configuration.
#
# Discriminated on the `backend` key, so Puppet validates the right set of
# parameters for the backend you actually asked for rather than accepting a
# soup of optional keys.
type Certmanager::Issuerconfig = Variant[
  Certmanager::Acmeconfig,
  Certmanager::Digicertconfig,
  Certmanager::Selfsignedconfig,
]
