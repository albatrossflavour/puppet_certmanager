# frozen_string_literal: true

require 'puppet/resource_api'

Puppet::ResourceApi.register_type(
  name: 'certmanager_placeholder',
  docs: <<~DOC,
    @summary Guarantees something certificate-shaped exists at the canonical path.

    Exists to break the first-run deadlock. nginx will not start without a
    certificate file, an `http-01` challenge cannot succeed without a web
    server answering, and the certificate does not exist until the challenge
    succeeds. Three things each waiting on the other.

    This resource writes a short-lived self-signed certificate into the
    store if, and only if, the store is empty. It never overwrites a real
    certificate: replacing a valid public certificate with a self-signed one
    as a side effect of a Puppet run would be considerably worse than the
    problem it solves.

    Order it before the consuming service and let `certmanager_certificate`
    notify that service once the real certificate lands:

    ```puppet
    Certmanager_placeholder['www.example.com'] -> Service['nginx']
    Certmanager_certificate['www.example.com'] ~> Service['nginx']
    ```

    The `certmanager` fact reports a placeholder as `self_signed` and lists
    it under `placeholders`, so a certificate stuck on its bootstrap is
    visible rather than quietly serving a certificate nobody trusts.
  DOC
  features: ['simple_get_filter'],
  attributes: {
    ensure: {
      type: 'Enum[present]',
      desc: 'Placeholders are only ever created. Removal is the real certificate replacing them.',
      default: 'present',
    },
    name: {
      type: 'String[1]',
      desc: 'Certificate name, matching the certmanager_certificate it bootstraps.',
      behaviour: :namevar,
    },
    common_name: {
      type: 'Optional[String[1]]',
      desc: 'Subject common name. Defaults to the resource title.',
      behaviour: :parameter,
    },
    san: {
      type: 'Array[String[1]]',
      desc: 'DNS names to put on the placeholder, so a virtual host matching on SNI still works.',
      behaviour: :parameter,
      default: [],
    },
    key_type: {
      type: 'Enum[ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-2048, rsa-3072, rsa-4096]',
      desc: 'Key type for the placeholder. Matching the real certificate avoids a needless key change on issuance.',
      behaviour: :parameter,
      default: 'ecdsa-p256',
    },
    validity_days: {
      type: 'Integer[1, 3650]',
      desc: <<~DESC,
        How long the placeholder is valid for. Short on purpose: a
        placeholder that outlives its welcome is a placeholder nobody
        noticed, and a monitoring alert in a fortnight is better than a
        self-signed certificate serving production for a year.
      DESC
      behaviour: :parameter,
      default: 30,
    },
    subject: {
      type: 'Hash[String[1], String[1]]',
      desc: 'Additional subject components.',
      behaviour: :parameter,
      default: {},
    },
  },
)
