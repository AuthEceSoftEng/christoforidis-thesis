/**
 * Common sinks predicates for JavaScript
 */

 import javascript
 import semmle.javascript.security.dataflow.SqlInjectionQuery as SqlInjection
 import semmle.javascript.security.dataflow.NosqlInjectionQuery as NosqlInjection
 import semmle.javascript.security.dataflow.CommandInjectionQuery as CommandInjection
 import semmle.javascript.security.dataflow.IndirectCommandInjectionQuery as IndirectCommandInjection
 import semmle.javascript.security.dataflow.SecondOrderCommandInjectionQuery as SecondOrderCommandInjection
 import semmle.javascript.security.dataflow.ReflectedXssQuery as ReflectedXss
 import semmle.javascript.security.dataflow.StoredXssQuery as StoredXss
 import semmle.javascript.security.dataflow.CodeInjectionQuery as CodeInjection
 import semmle.javascript.security.dataflow.UnsafeDeserializationQuery as UnsafeDeserialization
 import semmle.javascript.security.dataflow.LogInjectionQuery as LogInjection
 import semmle.javascript.security.dataflow.ClientSideRequestForgeryQuery as ClientSideRequestForgery
 import semmle.javascript.security.dataflow.RequestForgeryQuery as RequestForgery

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

// holds if the given node is an HTTP response sink
predicate isHttpResponseSink(DataFlow::Node node) {
  // Standard XSS sinks from the libraries
  node instanceof ReflectedXss::Sink
  or
  node instanceof StoredXss::Sink
  or
  // Express.js response methods
  exists(DataFlow::CallNode call |
    // Express response methods - broader list
    call.getCalleeNode().(DataFlow::PropRead).getPropertyName() in [
      "send", "write", "end", "json", "jsonp", "render", "sendFile", 
      "sendStatus", "setHeader", "attachment", "download", "type"
    ] and
    // Improved response object detection
    (
      // By parameter name (res or response)
      exists(Parameter p |
        p = call.getCalleeNode().(DataFlow::PropRead).getBase().getALocalSource().asExpr().(VarAccess).getVariable().getADeclaration() and
        (p.getName() = "res" or p.getName() = "response")
      )
      or
      // By route handler position
      exists(DataFlow::CallNode routeCall |
        routeCall.getCalleeNode().(DataFlow::PropRead).getPropertyName() in ["get", "post", "put", "delete", "use", "all"] and
        call.getCalleeNode().(DataFlow::PropRead).getBase().getALocalSource() = 
          routeCall.getArgument(1).getAFunctionValue().getParameter(1)
      )
    ) and
    // Content being sent - could be 1st or 2nd argument depending on method
    (
      node = call.getArgument(0) or 
      node = call.getArgument(1)
    )
  )
  or
  // Chained Express methods (status().json(), etc.)
  exists(DataFlow::CallNode chainedCall |
    // Terminal methods that output content
    chainedCall.getCalleeNode().(DataFlow::PropRead).getPropertyName() in [
      "json", "send", "end", "render"
    ] and
    // The base is another method call (like status())
    chainedCall.getCalleeNode().(DataFlow::PropRead).getBase() instanceof DataFlow::CallNode and
    // The content
    node = chainedCall.getArgument(0)
  )
  or
  // Koa response patterns
  exists(DataFlow::PropWrite bodyWrite |
    bodyWrite.getPropertyName() = "body" and
    (
      bodyWrite.getBase().asExpr().(VarAccess).getVariable().getName() in ["ctx", "context"] or
      bodyWrite.getBase().(DataFlow::PropRead).getPropertyName() in ["ctx", "context", "response"]
    ) and
    node = bodyWrite.getRhs()
  )
}

// holds if the given node is a dynamic code execution sink
predicate isDynamicCodeExecutionSink(DataFlow::Node node) {
  node instanceof CodeInjection::Sink
  or
  exists(DataFlow::CallNode call |
    // Direct eval calls
    call.getCalleeNode().getALocalSource() = DataFlow::globalVarRef("eval") and
    node = call.getArgument(0)
    or
    // Function constructor
    call instanceof DataFlow::NewNode and
    call.getCalleeNode().getALocalSource() = DataFlow::globalVarRef("Function") and
    (node = call.getAnArgument() and not node = call.getLastArgument())
    or
    // setTimeout/setInterval with string first argument
    call.getCalleeNode().getALocalSource() = DataFlow::globalVarRef(["setTimeout", "setInterval"]) and
    node = call.getArgument(0) and
    not exists(DataFlow::FunctionNode f | f.flowsTo(node))
    or
    // Indirect eval via window/global/this
    call.getCalleeNode().(DataFlow::PropRead).getPropertyName() = "eval" and
    call.getCalleeNode().(DataFlow::PropRead).getBase().getALocalSource() = 
      DataFlow::globalVarRef(["window", "global", "globalThis"]) and
    node = call.getArgument(0)
    or
    // Template engine sinks
    (
      // EJS template rendering
      call.getCalleeNode().(DataFlow::PropRead).getPropertyName() = "render" and
      exists(DataFlow::SourceNode base | base = call.getCalleeNode().(DataFlow::PropRead).getBase().getALocalSource() |
        base.toString().matches("%ejs%")
      ) and
      node = call.getArgument(0)
    )
    or
    (
      // Handlebars/Pug compilation
      call.getCalleeNode().(DataFlow::PropRead).getPropertyName() = "compile" and
      exists(DataFlow::SourceNode base | base = call.getCalleeNode().(DataFlow::PropRead).getBase().getALocalSource() |
        base.toString().matches("%handlebars%") or base.toString().matches("%pug%")
      ) and
      node = call.getArgument(0)
    )
  )
}

// holds if the given node is a deserialization sink
predicate isDeserializationSink(DataFlow::Node node) {
  node instanceof UnsafeDeserialization::Sink
  or
  exists(DataFlow::CallNode call |
    // JSON.parse
    call.getCalleeNode() = DataFlow::globalVarRef("JSON").getAPropertyRead("parse") and
    node = call.getArgument(0)
    or
    // YAML libraries (js-yaml)
    exists(DataFlow::SourceNode yaml |
      yaml = DataFlow::moduleImport("js-yaml") or
      yaml = DataFlow::moduleImport("yaml")
    |
      call = yaml.getAMemberCall("load") and
      node = call.getArgument(0)
    )
    or
    // Node-serialize
    exists(DataFlow::SourceNode serialize |
      serialize = DataFlow::moduleImport("node-serialize")
    |
      call = serialize.getAMemberCall("unserialize") and 
      node = call.getArgument(0)
    )
    or
    // XML parsing with XXE risk
    exists(DataFlow::SourceNode xml2js |
      xml2js = DataFlow::moduleImport("xml2js")
    |
      call = xml2js.getAMemberCall("parseString") and
      node = call.getArgument(0) and
      // Look for missing/unsafe XML parser options
      not exists(DataFlow::ObjectLiteralNode options |
        options = call.getArgument(1) and
        exists(BooleanLiteral bl |
          bl.getValue() = "false" and
          options.hasPropertyWrite("noent", DataFlow::valueNode(bl))
        )
      )
    )
    or
    // Query string parsing
    exists(DataFlow::SourceNode qs |
      qs = DataFlow::moduleImport("qs") or
      qs = DataFlow::moduleImport("querystring")
    |
      call = qs.getAMemberCall("parse") and
      node = call.getArgument(0)
    )
  )
}

// holds if the given node is a logging sink
predicate isLoggingSink(DataFlow::Node node) {
  node instanceof LogInjection::Sink
  or
  // Console logging
  exists(DataFlow::CallNode call |
    call.getCalleeNode() = DataFlow::globalVarRef("console").getAPropertyRead(["log", "error", "warn", "info", "debug"]) and
    node = call.getAnArgument()
  )
  or
  // Winston logger
  exists(DataFlow::CallNode call, DataFlow::SourceNode winston |
    winston = DataFlow::moduleImport("winston") and
    (
      // winston.log/info/warn/error
      call = winston.getAMemberCall(["log", "info", "warn", "error", "debug"]) or
      // logger instance methods
      exists(DataFlow::SourceNode logger |
        logger = winston.getAPropertyRead("createLogger").getACall() and
        call = logger.getAMemberCall(["log", "info", "warn", "error", "debug"])
      )
    ) and
    node = call.getAnArgument()
  )
  or
  // Bunyan
  exists(DataFlow::CallNode call, DataFlow::SourceNode bunyan |
    bunyan = DataFlow::moduleImport("bunyan") and
    exists(DataFlow::SourceNode logger |
      logger = bunyan.getAMethodCall("createLogger") and
      call = logger.getAMemberCall(["info", "warn", "error", "debug", "trace"]) and
      node = call.getAnArgument()
    )
  )
  or
  // Pino
  exists(DataFlow::CallNode call, DataFlow::SourceNode pino |
    pino = DataFlow::moduleImport("pino") and
    exists(DataFlow::SourceNode logger |
      logger = pino.getACall() and
      call = logger.getAMemberCall(["info", "warn", "error", "debug", "trace", "fatal"]) and
      node = call.getAnArgument()
    )
  )
  or
  // Morgan (Express logging middleware)
  exists(DataFlow::CallNode call |
    call = DataFlow::moduleImport("morgan").getACall() and
    exists(DataFlow::ObjectLiteralNode options |
      options = call.getArgument(1) and
      node = options.getAPropertyWrite("stream").getRhs()
    )
  )
}

// holds if the given node is an external API call sink
predicate isExternalApiSink(DataFlow::Node node) {
  node instanceof ClientSideRequestForgery::Sink
  or
  node instanceof RequestForgery::Sink
  or
  // Axios library
  exists(DataFlow::CallNode call |
    (
      // axios(config) or axios.get/post/put/delete/etc
      (
        call.getCalleeNode() = DataFlow::moduleImport("axios") or
        call.getCalleeNode().(DataFlow::PropRead).getBase() = DataFlow::moduleImport("axios")
      ) and
      (
        // URL is first argument for method calls
        call.getCalleeNode().(DataFlow::PropRead).getPropertyName() in ["get", "post", "put", "delete", "patch", "head", "options"] and
        node = call.getArgument(0)
        or
        // URL is in config object
        exists(DataFlow::ObjectLiteralNode config |
          config = call.getArgument(0) and
          node = config.getAPropertyWrite("url").getRhs()
        )
      )
    )
  )
  or
  // Fetch API (browser or node-fetch)
  exists(DataFlow::CallNode call |
    (
      call.getCalleeNode() = DataFlow::globalVarRef("fetch") or
      call.getCalleeNode() = DataFlow::moduleImport("node-fetch")
    ) and
    node = call.getArgument(0)
  )
  or
  // Request library
  exists(DataFlow::CallNode call |
    call.getCalleeNode() = DataFlow::moduleImport("request") and
    (
      // String URL as first argument
      node = call.getArgument(0)
      or
      // URL in options object
      exists(DataFlow::ObjectLiteralNode options |
        options = call.getArgument(0) and
        node = options.getAPropertyWrite("url").getRhs()
      )
    )
  )
  or
  // Native http/https modules
  exists(DataFlow::CallNode call |
    (
      call.getCalleeNode().(DataFlow::PropRead).getPropertyName() = "request" and
      (
        call.getCalleeNode().(DataFlow::PropRead).getBase() = DataFlow::moduleImport("http") or
        call.getCalleeNode().(DataFlow::PropRead).getBase() = DataFlow::moduleImport("https")
      )
    ) and
    (
      // String URL as first argument
      node = call.getArgument(0)
      or
      // URL in options object
      exists(DataFlow::ObjectLiteralNode options |
        options = call.getArgument(0) and
        (
          node = options.getAPropertyWrite("host").getRhs() or
          node = options.getAPropertyWrite("hostname").getRhs() or
          node = options.getAPropertyWrite("path").getRhs() or
          node = options.getAPropertyWrite("port").getRhs()
        )
      )
    )
  )
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