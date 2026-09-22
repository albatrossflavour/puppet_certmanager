# @summary A credential supplied to the module.
#
# Either a literal value (wrapped in `Sensitive`, normally from eyaml) or a
# `Deferred` that resolves on the agent at apply time, so the value never
# lands in the catalog or in PuppetDB.
type Certmanager::Secret = Variant[Sensitive[String[1]], Deferred]
