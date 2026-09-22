# frozen_string_literal: true

# The path to this module's own `lib` directory in the current environment.
#
# Needed because the deploy hook and the fact-cache refresh job are plain
# Ruby scripts run outside any Puppet run, so they have to be told where the
# module's libraries are. On an agent, pluginsync has already copied them
# into the vardir and that is the answer. Under `puppet apply` it has not,
# and this is.
#
# Returns undef when the module cannot be located, which is the normal case
# when the catalogue was compiled on a server: the server's module path
# means nothing on the agent, and the vardir copy is the right answer there
# anyway.
Puppet::Functions.create_function(:'certmanager::module_libdir', Puppet::Functions::InternalFunction) do
  # @return [Optional[String]] Absolute path to the module's lib directory.
  dispatch :module_libdir do
    scope_param
    return_type 'Optional[String]'
  end

  def module_libdir(scope)
    mod = scope.environment.module('certmanager')
    return nil if mod.nil?

    path = File.join(mod.path, 'lib')
    File.directory?(path) ? path : nil
  end
rescue StandardError
  nil
end
