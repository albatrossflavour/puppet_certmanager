# certmanager

[![CI](https://github.com/albatrossflavour/puppet_certmanager/actions/workflows/ci.yml/badge.svg)](https://github.com/albatrossflavour/puppet_certmanager/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Certificate lifecycle management for Puppet. Let's Encrypt, DigiCert and self-signed behind one resource shape, one place on disk, and a fact that tells you what is about to expire.

## What problem this solves

Most certificate automation stops at "certbot got a certificate". The awkward parts come after that.

nginx needs a path. If that path is `/etc/letsencrypt/live/www.example.com/fullchain.pem`, then every config file referencing it is wrong the day you move that certificate to a commercial CA. So this module owns a canonical layout and the issuer backend's job is to land files there:

```text
/etc/certmanager/certs/www.example.com/
  cert.pem  chain.pem  fullchain.pem  privkey.pem  combined.pem  bundle.p12  cert.json
```

nginx points at `/etc/certmanager/certs/www.example.com/fullchain.pem` and never knows which CA signed it.

certbot renews on its own timer, with no catalog anywhere in sight. Without something to catch that, a certificate renews perfectly and every service on the host carries on serving the old one until Puppet next happens to run. So consumers get a deploy hook as well as a Puppet relationship.

And the certificate that takes the service down at 2am is almost never the one in your manifests. It is the one somebody deployed by hand in 2019. So the fact reports on certificates this module did not issue, if you point it at the directories where they live.

## Quick start

```puppet
class { 'certmanager':
  default_issuer => 'letsencrypt',
  issuers        => {
    'letsencrypt' => {
      'backend'       => 'acme',
      'directory_url' => 'https://acme-v02.api.letsencrypt.org/directory',
      'email'         => 'certs@example.com',
      'webroot'       => '/var/www/html',
    },
  },
}

certmanager::certificate { 'www.example.com':
  san => ['example.com'],
}

certmanager::consumer { 'nginx-www':
  certificate => 'www.example.com',
  service     => 'nginx',
}
```

In the nginx config:

```puppet
ssl_certificate     <%= certmanager::path('www.example.com', 'fullchain') %>;
ssl_certificate_key <%= certmanager::path('www.example.com', 'privkey') %>;
```

## The first-run deadlock

nginx will not start without a certificate file. The `http-01` challenge cannot succeed without a web server answering on port 80. The certificate does not exist until the challenge succeeds. Three things, each waiting on the other.

`certmanager::certificate` plants a short-lived self-signed placeholder at the canonical path before the real issuer runs. nginx starts on a certificate nobody trusts, the challenge succeeds, the real certificate replaces it, the consumer reloads.

The ordering is deliberate. The placeholder runs *before* the service, so the service can start. The certificate only *notifies* the service, so a failed issuance leaves nginx running on the placeholder rather than skipping it entirely and taking the site down to fix a certificate problem.

The fact reports a placeholder that is still in place under `placeholders`, and the placeholder is valid for 30 days rather than a year, so one that nobody noticed sets off an alert in a fortnight instead of quietly serving production.

Turn it off with `bootstrap => false` if you validate through DNS and nothing depends on the file existing first.

## Issuers

An issuer is a named instance of a backend. Several instances of the same backend are normal and usually wanted:

```puppet
issuers => {
  'letsencrypt' => {
    'backend'       => 'acme',
    'directory_url' => 'https://acme-v02.api.letsencrypt.org/directory',
    'email'         => 'certs@example.com',
  },
  'staging' => {
    'backend'       => 'acme',
    'directory_url' => 'https://acme-staging-v02.api.letsencrypt.org/directory',
    'email'         => 'certs@example.com',
  },
}
```

Let's Encrypt rate limits are per registered domain and the penalty for tripping one is an hour's lockout, so having a staging issuer to point at while you are working things out saves a lot of grief.

### acme

Wraps certbot on POSIX and win-acme on Windows. The client owns its account state and its renewal timer, which is the right place for it: reimplementing ACME in a Puppet provider means reimplementing account key rotation, nonce handling and retry backoff, all of which certbot already gets right.

Puppet owns configuration and first issuance. The client owns renewal. The store is mirrored from the client's output.

DNS validation, which is the only way to get a wildcard and the only way to issue for a host the internet cannot reach:

```puppet
'letsencrypt' => {
  'backend'                 => 'acme',
  'directory_url'           => 'https://acme-v02.api.letsencrypt.org/directory',
  'email'                   => 'certs@example.com',
  'challenge'               => 'dns-01',
  'dns_plugin'              => 'cloudflare',
  'dns_credentials'         => Sensitive(lookup('cloudflare_certbot_ini')),
  'dns_propagation_seconds' => 60,
}
```

`dns_propagation_seconds` is the setting that actually matters. certbot's defaults assume the provider's best case, and a slow zone transfer means the CA looks for the record before it exists. If your `dns-01` validations fail intermittently, this is why.

A host that reaches the internet through a proxy, or an ACME endpoint signed by a CA the system has never heard of, needs environment settings rather than flags, because certbot offers no flags for either:

```puppet
'internal-acme' => {
  'backend'       => 'acme',
  'directory_url' => 'https://acme.internal.example.com/directory',
  'email'         => 'certs@example.com',
  'environment'   => {
    'HTTPS_PROXY'        => 'http://proxy.example.com:3128',
    'REQUESTS_CA_BUNDLE' => '/etc/pki/tls/certs/internal-ca.pem',
  },
}
```

One limitation worth knowing before you rely on it. This applies when certmanager runs certbot, which is issuance and anything Puppet drives. certbot's own renewal timer is a systemd unit this module does not manage, and it runs with none of it. For a public CA that makes no difference. For a private ACME endpoint it means renewals work under Puppet and fail on the timer, so put that CA in the system trust store as well and treat this setting as covering issuance only.

Commercial ACME endpoints (ZeroSSL, Buypass, DigiCert's own ACME service) want External Account Binding:

```puppet
'zerossl' => {
  'backend'       => 'acme',
  'directory_url' => 'https://acme.zerossl.com/v2/DV90',
  'eab_kid'       => lookup('zerossl_kid'),
  'eab_hmac_key'  => Sensitive(lookup('zerossl_hmac')),
}
```

### digicert

CertCentral's REST API. Nothing like ACME: orders cost money, and depending on the product and your organisation's validation state an order can sit pending for days waiting on a human at DigiCert.

```puppet
'digicert' => {
  'backend'         => 'digicert',
  'api_key'         => Sensitive(lookup('digicert_api_key')),
  'organization_id' => 12345,
  'product_name_id' => 'ssl_securesite_flex',
  'validity_years'  => 1,
}
```

Three things follow from orders costing money:

Order state is kept on the host. Placing a duplicate order because Puppet ran again before the first one finished validating is a billing incident, not a retry.

A pending order is a normal state. The run reports it and moves on; it does not try to fix it.

The private key never leaves the host. Puppet generates it and sends a CSR.

### selfsigned

For labs, for internal services nothing outside can reach, and for the bootstrap placeholder.

```puppet
'internal' => {
  'backend'       => 'selfsigned',
  'validity_days' => 365,
  'subject'       => { 'O' => 'Example Ltd', 'C' => 'AU' },
}
```

## Consumers

`certmanager::consumer` does two jobs because there are two renewal paths.

On a Puppet run, `Certmanager_certificate` notifies the service. That covers first issuance and anything Puppet changed.

Between Puppet runs, the ACME client renews on its own timer and Puppet never sees it. So the consumer also writes a deploy hook, which the backend runs after any out-of-band renewal.

```puppet
certmanager::consumer { 'nginx-www':
  certificate => 'www.example.com',
  service     => 'nginx',
}
```

The service relationship goes through a collector, so declaring a consumer for a service managed in another module, or not managed at all, does not fail compilation.

For a service that insists on its own copy of the certificate with its own ownership:

```puppet
certmanager::consumer { 'postfix-mail':
  certificate    => 'mail.example.com',
  service        => 'postfix',
  commands       => [
    'install -o postfix -g postfix -m 0600 "$CERTMANAGER_PRIVKEY" /etc/postfix/tls/key.pem',
    'install -o root -g root -m 0644 "$CERTMANAGER_FULLCHAIN" /etc/postfix/tls/cert.pem',
  ],
  reload_command => 'systemctl reload postfix',
  only_if        => 'systemctl is-active --quiet postfix',
}
```

The hook gets the store's paths in its environment (`CERTMANAGER_FULLCHAIN`, `CERTMANAGER_PRIVKEY`, and so on), so it never hardcodes a path either. `only_if` stops a stopped service producing a failed hook that buries the real ones.

Hooks are best effort by design. One service's broken reload script must not stop the other services on the host picking up a renewed certificate, and must not fail the Puppet run that renewed it. Failures are logged with the name of the hook that failed.

## What counts as drift

A certificate is not a conventional resource. Whether it is correct depends on the clock and on the names it carries, not on whether the file is there. Four things are checked on every run:

- the certificate exists
- it is not inside its renewal window (`renew_before_days`, default 30)
- its SAN list matches what was declared, in any order
- its key type matches what was declared

Adding a name to `san` reissues. Changing `key_type` from RSA to ECDSA reissues. A bootstrap placeholder still sitting where a real certificate should be counts as drift, so an issuance that quietly fails every night does not stay quiet.

## The fact

```json
{
  "certmanager": {
    "certificates": {
      "www.example.com": {
        "managed": true,
        "issuer": "letsencrypt",
        "backend": "acme",
        "not_after": "2026-12-01T10:22:00Z",
        "days_left": 70,
        "expired": false,
        "self_signed": false,
        "san": ["example.com", "www.example.com"],
        "key_type": "ecdsa-p256",
        "consumers": ["nginx-www.sh"]
      }
    },
    "count": 1,
    "managed_count": 1,
    "expired": [],
    "expiring_critical": [],
    "expiring_soon": [],
    "placeholders": [],
    "soonest_expiry": 70,
    "warnings": {}
  }
}
```

The fact reads a cache rather than parsing every certificate on every run. The cache is rebuilt on a schedule, whenever this module issues a certificate, and whenever the ACME deploy hook fires. If the cache is missing or stale that shows up in `warnings`, because a fact quietly reporting zero certificates is worse than one reporting nothing: it looks like good news.

To find the certificates nobody put in Puppet:

```puppet
class { 'certmanager':
  scan_directories => ['/etc/pki/tls/certs', '/opt/app/ssl'],
  scan_recursive   => true,
}
```

The scan is empty by default and opens only `.pem`, `.crt` and `.cer`. It never reads private keys, and it skips self-signed certificates with no SAN, which is what a CA root in a trust bundle looks like. Pointing it at `/etc/ssl/certs` would otherwise find several hundred roots and bury everything that matters.

### Querying the estate

```sh
puppet query 'inventory[certname] { facts.certmanager.expiring_soon ~ ".+" }'
puppet query 'inventory[certname] { facts.certmanager.placeholders ~ ".+" }'
```

## Tasks

```sh
bolt task run certmanager::report --targets web --expiring_within 30
bolt task run certmanager::renew --targets web1 certificate=www.example.com
bolt task run certmanager::refresh_facts --targets all
```

`renew` needs nothing but the certificate's name for an ACME certificate: the store records which backend issued it and certbot holds its own account state. DigiCert is the exception, because an order needs an API key and that quite deliberately does not live on the host.

## Secrets

Credentials come in as `Sensitive` parameters, normally from eyaml. The module writes them at mode 0600 with `show_diff => false` and never logs them.

For sites that would rather no secret ever landed in a catalog or in PuppetDB, every credential also accepts a `Deferred`, resolved on the agent at apply time:

```puppet
'digicert' => {
  'backend'         => 'digicert',
  'api_key'         => Deferred('vault_lookup::lookup', ['secret/digicert', 'https://vault.example.com:8200']),
  'organization_id' => 12345,
}
```

## Removing a certificate

`ensure => absent` revokes with the CA and leaves the files alone. Removing a certificate from a manifest is usually a refactor, and losing the key to one is not recoverable. Add `purge => true` when you mean it.

## Platform notes

RHEL family: certbot comes from EPEL. This module does not enable EPEL for you. Pulling in a third-party repository as a side effect of asking for a certificate is not a decision a certificate module gets to make on your behalf.

SLES: certbot availability is patchy across service packs. If it is not in your repositories, set `manage_packages => false` and point `certbot_path` at your own installation.

Windows: win-acme rather than certbot, driven with the same parameters. `wacs_package_provider` is unset by default, so naming chocolatey here does not make every Windows node depend on the chocolatey module.

If certbot comes from snap or a virtualenv anywhere, set `manage_packages => false` rather than fighting the package provider over it.

## Reference

Full parameter documentation is in [REFERENCE.md](REFERENCE.md).

## Development

```sh
pdk bundle install
pdk bundle exec rake spec_prep
pdk validate
pdk bundle exec rspec
COVERAGE=yes pdk bundle exec rspec spec/unit   # line coverage, gated at 95% in CI
```

[CONTRIBUTING.md](CONTRIBUTING.md) covers the gates, the toolchain traps and the conventions that will look odd until somebody explains them. [CLAUDE.md](CLAUDE.md) covers the architecture and the things that will bite you.

Security reports go through [GitHub's private vulnerability reporting](https://github.com/albatrossflavour/puppet_certmanager/security/advisories/new), not a public issue. [SECURITY.md](SECURITY.md) says what counts as a vulnerability in a module that handles private keys, and what does not.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
