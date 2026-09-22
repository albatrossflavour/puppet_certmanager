# @summary Name of a configured issuer backend.
#
# Issuers are declared in `certmanager::issuers` and resolved at catalog
# compile time. The three built-in backends are `acme`, `digicert` and
# `selfsigned`; the value here is the *instance* name, so you can have several
# ACME issuers (staging and production, for example) side by side.
type Certmanager::Issuer = Pattern[/\A[a-z0-9][a-z0-9_-]*\z/]
