# Security policy

## Reporting a vulnerability

**Do not open a public issue.**

Use [GitHub's private vulnerability reporting](https://github.com/albatrossflavour/puppet_certmanager/security/advisories/new). It opens a draft advisory that only you and the maintainers can see, and it keeps the discussion attached to the code.

This is a personally maintained module, not a vendor product. There is no security team behind it and no published response time, so this file does not invent one. What you will get is an acknowledgement, an honest assessment of severity, and a fix or a clear statement that it will not be fixed.

## What to include

The more of this you have, the faster the first reply stops being a request for more information.

- Which version. `metadata.json` carries it.
- Which part. The issuer backends, the certificate store, the fact, the Bolt tasks and the manifests have very different blast radii, and the first triage question is always which one.
- What an attacker gets, and what position they need to be in to get it. A finding that needs root on the host already is a different conversation from one that needs a network route.
- A reproduction, if you have one.

## What this module handles, and what that means

Worth stating plainly, because it shapes what counts as a vulnerability here.

**Private keys.** The module generates them, writes them to `/etc/certmanager/certs/<name>/privkey.pem` at mode 0600, and never sends them anywhere. The DigiCert backend sends a CSR and keeps the key on the host. Anything that causes key material to be written world-readable, logged, sent off the host, or left in a temporary file is a vulnerability, not a bug.

**Credentials.** ACME external account bindings, DNS plugin credentials and DigiCert API keys arrive as `Sensitive` parameters or as `Deferred` values resolved on the agent. They are written at mode 0600 with `show_diff => false`. Anything that puts one in a catalogue, a report, a log line, an exception message or PuppetDB is a vulnerability.

**Deploy hooks.** `certmanager::consumer` writes shell or PowerShell scripts that run as root when a certificate changes, with the certificate's paths in the environment. The content comes from the catalogue, so anyone who can write your Hiera data can already run code as root on the node. That is inherent to Puppet rather than specific to this module, but a way to influence hook content from outside the catalogue would be a real finding.

**The certificate scan.** `scan_directories` opens files on paths the operator configures. It opens `.pem`, `.crt` and `.cer` only, and deliberately never reads private keys. A path traversal, a way to make it read something outside its configured directories, or a way to make it report key material would all be findings.

## Out of scope

Certificates expiring because issuance failed and nobody was watching. The fact reports `expired`, `expiring_soon`, `expiring_critical` and `placeholders` precisely so monitoring can catch that, and wiring monitoring up is the operator's job.

A self-signed bootstrap placeholder being served to clients. That is the documented behaviour that stops a web server failing to start, it is reported in the fact under `placeholders`, and it is short-lived by default so it sets off an alert rather than serving quietly for a year.
