# Contributing to certmanager

The short version of how work gets done here: what has to pass, what the toolchain wants, and the handful of conventions that will look odd until somebody explains them.

The architecture and the traps are in [CLAUDE.md](CLAUDE.md), which is written for anyone touching the code, not only for Claude. Read that before changing anything under `lib/`.

## Getting a working checkout

```console
pdk bundle install
pdk bundle exec rake spec_prep    # installs the fixture modules
pdk validate
pdk bundle exec rspec
```

`spec_prep` matters. Without it every class and define spec dies on `Stdlib::Absolutepath`, which reads as a broken checkout rather than a missing step.

## The gates

CI runs all of these on every pull request, so you can run the relevant one before pushing rather than after.

| What | Command | When it matters |
| --- | --- | --- |
| Everything | `pdk validate` | Any change. Covers metadata, Puppet syntax, puppet-lint and RuboCop |
| Unit specs | `pdk bundle exec rspec` | Any change |
| Line coverage | `COVERAGE=yes pdk bundle exec rspec` | Any change under `lib/` |
| REFERENCE.md | `pdk bundle exec puppet strings generate --format markdown --out REFERENCE.md` | Any parameter or docstring change |
| Markdown | `markdownlint-cli2 "**/*.md"` | Any prose change |

`REFERENCE.md` is generated. Do not hand-edit it; regenerate it and commit the result. CI fails if it is stale.

## Conventions worth knowing

**Certificates in specs are generated, never committed.** A committed certificate expires and the suite starts failing on a date nobody wrote down. `spec/spec_helper_local.rb` builds them, with an hour of slack past the requested window so `days_left` does not come back one short at random.

**Sign spec certificates with the test CA unless you mean self-signed.** A self-signed certificate recorded against a real CA backend is correctly reported as a leftover bootstrap placeholder. A spec that gets this wrong tests the fixture rather than the code.

**Catalogue tests prove nothing about providers.** The first version of this module had 1615 passing examples and four real bugs, including one that reissued the certificate on every Puppet run. All four were found within ten minutes of applying it against a real certbot and a real CA. If you change a provider or an issuer backend, exercise it against something that actually issues.

**Adding a CA should touch two files.** One new class under `lib/puppet_x/certmanager/issuer/`, and one entry in `Issuer::BACKENDS`. If it needs more than that, the abstraction has leaked, and that is the bug to fix first.

## RuboCop and puppet-lint configuration

`.rubocop.yml` is generated from the PDK template. Module-local settings live in `.sync.yml` as well, so a working `pdk update` reproduces them, and are repeated in `.rubocop.yml` under a clearly marked block because pdk 3.8.0 with template 3.9.0 does not currently apply `.sync.yml`'s `default_configs`.

Extend the template's existing cop blocks rather than appending a second definition. YAML duplicate keys silently win and take the template's `EnforcedStyle` with them, which is how a `Style/ClassAndModuleChildren` exclusion once turned into every provider being flagged.

## Pull requests

Branch off `main`. One logical change per pull request. New behaviour ships with the test that proves it: unit for logic, and a note in the PR describing what you exercised on a real host for anything touching issuance.

Say what you tested and how. "Applied against Pebble on a lab node, second run clean" is worth more than a paragraph of description.
