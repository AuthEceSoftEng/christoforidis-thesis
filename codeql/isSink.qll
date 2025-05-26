/**
 * Common sinks predicates for JavaScript
 */

 import javascript
 import semmle.javascript.security.dataflow.SqlInjectionQuery as SqlInjection
 import semmle.javascript.security.dataflow.NosqlInjectionQuery as NosqlInjection
 import semmle.javascript.security.dataflow.CommandInjectionQuery as CommandInjection
 import semmle.javascript.security.dataflow.IndirectCommandInjectionQuery as IndirectCommandInjection
 import semmle.javascript.security.dataflow.SecondOrderCommandInjectionQuery as SecondOrderCommandInjection


 /* POTENTIAL SINKS PREDICATES */
// holds if the given node is a command execution sink
predicate isCommandExecutionSink(DataFlow::Node node) {
  node instanceof CommandInjection::Sink
  or
  node instanceof IndirectCommandInjection::Sink
  or
  node instanceof SecondOrderCommandInjection::Sink
  or
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

// holds if the given node is a database query sink (SQL or NoSQL injection)
predicate isDatabaseQuerySink(DataFlow::Node node) {
  // SQL injection sinks from the standard library
  node instanceof SqlInjection::Sink
  or
  // NoSQL injection sinks from the standard library
  node instanceof NosqlInjection::Sink
}

/* PRIVATE HELPING PREDICATES */

// Command execution method names
private predicate isCommandExecMethodName(string name) {
  name = "exec" or name = "execSync" or
  name = "spawn" or name = "spawnSync" or
  name = "execFile" or name = "execFileSync"
}