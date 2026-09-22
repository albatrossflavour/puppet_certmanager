# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Apache-2.0 `LICENSE` text, which `metadata.json` had been declaring without shipping.
- `CONTRIBUTING.md`, `SECURITY.md` and `CODE_OF_CONDUCT.md`.
- A CI pipeline: validation, unit specs, a line-coverage floor, a check that `REFERENCE.md` is current, and markdownlint.
- Line coverage through SimpleCov, wired up in `spec/spec_helper_local.rb` and gated at 70%.

## [0.1.0] - 2026-09-22

First cut. Not yet published to the Forge.

### Added

- `certmanager::certificate`, the resource you actually declare, covering issuance, renewal and revocation.
- Issuer backends for ACME (certbot on POSIX, win-acme on Windows), DigiCert CertCentral, and self-signed.
- A canonical certificate store at `/etc/certmanager/certs/<name>/`, so consuming configuration points at one predictable path whoever signed the certificate.
- `certmanager::consumer`, which wires a service to a certificate through both a Puppet relationship and an ACME deploy hook, because renewals happen on certbot's timer with no catalogue in sight.
- A bootstrap placeholder that breaks the first-run deadlock where the web server will not start without a certificate and the challenge cannot succeed without the web server.
- The `certmanager` fact, reporting expiry, names, key type and consumers, for certificates this module did not issue as well as the ones it did.
- `certmanager::path()` and `certmanager::expiring()` functions.
- `certmanager::report`, `certmanager::renew` and `certmanager::refresh_facts` tasks.
- An `environment` setting on ACME issuers, for the certbot behaviour that has no flags: `HTTPS_PROXY` on a host that reaches the internet through a proxy, and `REQUESTS_CA_BUNDLE` when the ACME endpoint is signed by something the system trust store has never heard of.
- Support for RHEL 8/9 and derivatives, Debian 12, Ubuntu 22.04/24.04, SLES 15 and Windows Server 2019/2022/2025.

### Known issues

- An ACME issuer's `environment` covers certbot as this module runs it. certbot's own renewal timer is a systemd unit this module does not manage and does not see those settings, so a private ACME endpoint's CA needs to be in the system trust store as well.
- No acceptance tests. Verified by hand against a real certbot and a real ACME CA, not by Litmus.
- Never run through a PE agent with pluginsync, only masterless `puppet apply`.
- The DigiCert backend has been exercised against stubbed HTTP only. Placing a real order costs money.
- The Windows and win-acme path compiles and is unit tested but has never been executed on Windows.

[Unreleased]: https://github.com/albatrossflavour/puppet_certmanager/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/albatrossflavour/puppet_certmanager/releases/tag/v0.1.0
