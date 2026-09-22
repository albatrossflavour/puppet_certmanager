# Examples

Manifests you can read, and mostly apply, to see how the pieces fit.

They are deliberately runnable rather than illustrative. All of them compile under `puppet apply --noop` except the two that call `lookup()` for a credential, which need the Hiera key to exist first:

```sh
puppet apply --noop --modulepath /path/to/modules examples/selfsigned.pp
```

`selfsigned.pp`, `bootstrap.pp`, `inventory.pp` and `hiera_driven.pp` need nothing but Puppet. `letsencrypt_http.pp` compiles as it stands and needs certbot and a reachable CA to do anything. `letsencrypt_dns.pp` wants `cloudflare_certbot_ini` in Hiera. `digicert.pp` wants `digicert_api_key`, a CertCentral account, and will spend money, so it is the one to read rather than run.

| File | What it shows |
|---|---|
| `selfsigned.pp` | The smallest useful thing. No CA, no network, no credentials. |
| `letsencrypt_http.pp` | ACME over `http-01` behind an already-running web server, wired to nginx. |
| `letsencrypt_dns.pp` | ACME over `dns-01`, which is how you get a wildcard and how you issue for a host the internet cannot reach. |
| `digicert.pp` | A commercial certificate through CertCentral, with the order lifecycle that implies. |
| `bootstrap.pp` | The first-run deadlock and how the placeholder breaks it. |
| `inventory.pp` | Finding the certificates nobody put in Puppet. |
| `hiera_driven.pp` | The same thing declared entirely in data. |
