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

// holds if the given node is a file system operation sink
predicate isFileSystemSink(DataFlow::Node node) {
  // File write operations
  isFileWriteSink(node)
  or
  // File delete operations
  isFileDeleteSink(node)
  or
  // File create operations
  isFileCreateSink(node)
}

/* PRIVATE HELPING PREDICATES */

// Command execution method names
private predicate isCommandExecMethodName(string name) {
  name = "exec" or name = "execSync" or
  name = "spawn" or name = "spawnSync" or
  name = "execFile" or name = "execFileSync"
}

// holds if the given node is a file write operation sink
private predicate isFileWriteSink(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    (
      // Path argument in fs write methods
      exists(string methodName |
        isFileWriteMethodName(methodName) and
        (
          // Direct fs module method calls
          call = DataFlow::moduleMember("fs", methodName).getACall() or
          // fs.promises methods
          call = DataFlow::moduleMember("fs", "promises").getAPropertyRead(methodName).getACall()
        ) and
        // The first argument is the file path
        node = call.getArgument(0)
      )
      or
      // Content argument in fs write methods
      exists(string methodName |
        isFileWriteMethodName(methodName) and
        (
          // Direct fs module method calls
          call = DataFlow::moduleMember("fs", methodName).getACall() or
          // fs.promises methods
          call = DataFlow::moduleMember("fs", "promises").getAPropertyRead(methodName).getACall()
        ) and
        // The second argument is the content (for writeFile, appendFile)
        methodName.regexpMatch("write(File|FileSync)|append(File|FileSync)") and
        node = call.getArgument(1)
      )
    )
    or
    // Write streams path
    (
      call = DataFlow::moduleMember("fs", "createWriteStream").getACall() and
      // The first argument is the file path
      node = call.getArgument(0)
    )
    or
    // Write streams content
    (
      // Detect calls to write() on stream objects
      call.getCalleeNode().(DataFlow::PropRead).getPropertyName() = "write" and
      // The first argument is the content
      node = call.getArgument(0) and
      // Verify this is likely a file stream
      exists(DataFlow::CallNode createStream |
        createStream = DataFlow::moduleMember("fs", "createWriteStream").getACall() and
        call.getCalleeNode().(DataFlow::PropRead).getBase().getALocalSource() = createStream
      )
    )
  )
}

// holds if the given node is a file delete operation sink
private predicate isFileDeleteSink(DataFlow::Node node) {
  exists(DataFlow::CallNode call, string methodName |
    isFileDeleteMethodName(methodName) and
    (
      // Direct fs module method calls
      call = DataFlow::moduleMember("fs", methodName).getACall() or
      // fs.promises methods
      call = DataFlow::moduleMember("fs", "promises").getAPropertyRead(methodName).getACall()
    ) and
    // The first argument is the file path
    node = call.getArgument(0)
  )
}

// holds if the given node is a file creation operation sink
private predicate isFileCreateSink(DataFlow::Node node) {
  exists(DataFlow::CallNode call, string methodName |
    isFileCreateMethodName(methodName) and
    (
      // Direct fs module method calls
      call = DataFlow::moduleMember("fs", methodName).getACall() or
      // fs.promises methods
      call = DataFlow::moduleMember("fs", "promises").getAPropertyRead(methodName).getACall()
    ) and
    // The first argument is the file/directory path
    node = call.getArgument(0)
  )
}

// File write method names
private predicate isFileWriteMethodName(string name) {
  name = "writeFile" or name = "writeFileSync" or
  name = "appendFile" or name = "appendFileSync" or
  name = "write" or name = "writeSync"
}

// File delete method names
private predicate isFileDeleteMethodName(string name) {
  name = "unlink" or name = "unlinkSync" or
  name = "rmdir" or name = "rmdirSync" or
  name = "rm" or name = "rmSync"
}

// File create method names
private predicate isFileCreateMethodName(string name) {
  name = "mkdir" or name = "mkdirSync" or
  name = "mkdtemp" or name = "mkdtempSync" or
  name = "copyFile" or name = "copyFileSync" or
  name = "rename" or name = "renameSync"
}