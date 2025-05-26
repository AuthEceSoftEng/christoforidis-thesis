/**
 * Common sinks predicates for JavaScript
 */

 import javascript

// holds if the given node is a command execution sink
predicate isCommandExecutionSink(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    // The command argument is usually the first argument
    node = call.getArgument(0) and
    (
      // Direct calls on the child_process module
      exists(string methodName |
        isCommandExecMethodName(methodName) and
        call = DataFlow::moduleMember("child_process", methodName).getACall()
      )
      or
      // Track through variable assignments
      exists(DataFlow::SourceNode src, string methodName |
        isCommandExecMethodName(methodName) and
        src = DataFlow::moduleMember("child_process", methodName) and
        call.getCalleeNode() = src.getALocalSource()
      )
    )
  )
}

// Command execution method names
private predicate isCommandExecMethodName(string name) {
  name = "exec" or name = "execSync" or
  name = "spawn" or name = "spawnSync" or
  name = "execFile" or name = "execFileSync"
}