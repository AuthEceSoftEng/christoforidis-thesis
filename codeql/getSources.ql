/**
 * @name All Potential Vulnerability Sources in JavaScript
 * @description Identifies a broad range of untrusted or external data sources, including user input, environment variables, file reads....
 * @kind table
 * @id js/all-possible-sources
 * @tags inventory
 *       sources
 *       taint
 *       security
 */

 import javascript

 /* -- Source categories as predicates or classes -- */
 
 /* - Remote/user input sources via CodeQL library models -  */
 // All instances of RemoteFlowSource (e.g. Express, HTTP, Next.js, Firebase, etc.) 
 // are considered taint sources (remote/user input).
 predicate isRemoteSource(DataFlow::Node src) {
   src instanceof RemoteFlowSource
 }

 // over-approximates all possible sources of untrusted data in JavaScript.
 // even though RemoteFlowSource might cover most of the cases we will make sure to include all possible sources.

// Uses multiple heuristics to identify HTTP request sources across standard and custom frameworks:
// - Property name patterns (query, body, params, etc.)
// - Request object type detection
// - Parameter and variable name patterns
// - Property access patterns
// - Express-style route handler detection
// This complements RemoteFlowSource by catching sources in custom frameworks or non-standard patterns
predicate isHeuristicHttpRequestSource(DataFlow::Node src) {
  // Direct property access based on property names
  exists(PropAccess acc |
    acc = src.asExpr() and
    
    // Common request properties that may contain untrusted data
    acc.getPropertyName() in [
      // Standard properties
      "query", "params", "body", "headers", "cookies", "files",
      // URL and path related
      "url", "path", "originalUrl", "baseUrl", "hostname", "pathname",
      // Authentication related
      "user", "auth", "credentials",
      // Alternative naming conventions
      "payload", "data", "queryParameters", "requestParameters", "formData",
      // Headers-specific properties
      "authorization", "content", "origin", "referer", "userAgent"
    ] and
    
    (
      // Standard request object types
      acc.getBase().getType().toString() = "Request" or
      acc.getBase().getType().toString() = "IncomingMessage" or
      acc.getBase().getType().toString().matches("%Request%") or
      acc.getBase().getType().toString().matches("%Http%") or
      acc.getBase().getType().hasUnderlyingType("Request") or
      acc.getBase().getType().hasUnderlyingType("IncomingMessage") or
      acc.getBase().getType().hasUnderlyingType("ExpressRequest") or
      
      // Parameter name-based heuristics for custom frameworks
      exists(Parameter p |
        acc.getBase() = p.getAVariable().getAnAccess() and
        p.getName().toLowerCase().matches(["%req%", "%request%", "http%", "%session%"])
      ) or
      
      // Variable name-based heuristics
      exists(Variable v |
        acc.getBase() = v.getAnAccess() and
        v.getName().toLowerCase().matches(["%req%", "%request%", "http%", "%session%"])
      ) or
      
      // Property pattern heuristics (if an object has multiple request-like properties)
      exists(Variable v, int propertyCount |
        acc.getBase() = v.getAnAccess() and
        propertyCount = count(PropAccess otherAcc | 
          otherAcc.getBase() = v.getAnAccess() and
          otherAcc.getPropertyName() in ["body", "query", "params", "headers"]
        ) and
        propertyCount >= 2  // If object has at least 2 request-like properties
      ) or
      
      // Express/Connect convention detection
      exists(Function f, Parameter p |
        p = f.getParameter(0) and
        acc.getBase() = p.getAVariable().getAnAccess() and
        (
          f.getName().matches(["route", "get", "post", "put", "delete", "handler", "middleware"]) or
          exists(DataFlow::MethodCallNode call |
            call.getMethodName() in ["get", "post", "put", "delete", "use", "all", "options", "head", "patch"] and
            call.getArgument(_).getAFunctionValue().getFunction() = f
          )
        )
      )
    )
  )
}

// Detects GraphQL resolver arguments and context objects as sources of untrusted data.
// Identifies data coming from client requests through the GraphQL protocol in resolvers.
predicate isGraphQLRequestSource(DataFlow::Node src) {
  // Case 1: Direct property access to resolver arguments
  exists(PropAccess acc, Function f, Import imp |
    acc = src.asExpr() and
    
    // This access happens inside a function
    acc.getEnclosingFunction() = f and
    
    // The function is in a file with GraphQL imports
    imp.getImportedPath().getValue().regexpMatch(".*(graphql|apollo).*") and
    imp.getFile() = acc.getFile() and
    
    // The function has a resolver-like signature (3-4 parameters)
    f.getNumParameter() in [3, 4] and
    
    // Additional resolver identification heuristics
    (
      // Within a resolver object map (most common case)
      exists(ObjectExpr obj |
        obj.getPropertyByName(["Query", "Mutation", "Subscription"]).getInit() = f or
        obj.getPropertyByName(["Query", "Mutation", "Subscription"]).getInit()
          .(ObjectExpr).getAProperty().getInit() = f
      )
      or
      // Named with resolver-indicating name
      f.getName().regexpMatch(".*(query|resolver|mutation|subscription|Query|Resolver|Mutation|Subscription).*")
      or
      // Default case: rely on parameter pattern
      f.getParameter(0).getName() in ["parent", "root", "_", "obj", "source"] and
      f.getParameter(1).getName() in ["args", "arg", "arguments"] and
      f.getParameter(2).getName() in ["context", "ctx", "contextValue"]
    ) and
    
    // Common GraphQL resolver parameter patterns
    (
      // Standard pattern: (parent, args, context, info?)
      (
        f.getParameter(1).getName() in ["args", "arg", "arguments"] and
        acc.getBase() = f.getParameter(1).getAVariable().getAnAccess()
      )
      or
      (
        f.getParameter(2).getName() in ["context", "ctx", "contextValue"] and
        acc.getBase() = f.getParameter(2).getAVariable().getAnAccess()
      )
      or
      (
        f.getNumParameter() = 4 and
        f.getParameter(3).getName() = "info" and
        acc.getBase() = f.getParameter(3).getAVariable().getAnAccess()
      )
      or
      // Alternative pattern with underscore: (_, args, context)
      (
        f.getParameter(0).getName() = "_" and
        f.getParameter(1).getName() in ["args", "arg", "arguments"] and
        acc.getBase() = f.getParameter(1).getAVariable().getAnAccess()
      )
    )
  )
  or
  
  // Case 2: Nested property access (args.field.subfield or context.req.headers)
  exists(PropAccess innerAcc, PropAccess outerAcc, Function f, Import imp |
    // Inner property access is the source we're tracking
    innerAcc = src.asExpr() and
    
    // This happens in a function with GraphQL imports
    innerAcc.getEnclosingFunction() = f and
    imp.getImportedPath().getValue().regexpMatch(".*(graphql|apollo).*") and
    imp.getFile() = f.getFile() and
    
    // Get the base object access (outer property access)
    exists(Expr innerBase | 
      innerBase = innerAcc.getBase() and
      
      // Either directly or through a chain of property accesses
      (
        innerBase = outerAcc or 
        innerBase.getAChildExpr*() = outerAcc
      )
    ) and
    
    // Outer access is to a parameter in resolver position
    (
      outerAcc.getBase() = f.getParameter(1).getAVariable().getAnAccess() or
      outerAcc.getBase() = f.getParameter(2).getAVariable().getAnAccess() or
      (f.getNumParameter() = 4 and outerAcc.getBase() = f.getParameter(3).getAVariable().getAnAccess())
    ) and
    
    // Function has resolver pattern
    f.getNumParameter() in [3, 4]
  )
  or
  
  // Case 3: Variables derived from resolver parameters
  exists(Variable v, Function f, VariableDeclarator decl, Import imp |
    // Source is a property access on this variable
    exists(PropAccess pa |
      pa = src.asExpr() and
      pa.getBase() = v.getAnAccess()
    ) and
    
    // The variable was declared and initialized from a parameter
    decl.getBindingPattern().getAVariable() = v and 
    decl.getInit() = f.getParameter(1).getAVariable().getAnAccess() and
    f.getParameter(1).getName() in ["args", "arg", "arguments"] and
    
    // In the same function
    decl.getContainer() = f and
    
    // GraphQL verification
    imp.getImportedPath().getValue().regexpMatch(".*(graphql|apollo).*") and
    imp.getFile() = f.getFile() and
    f.getNumParameter() in [3, 4]
  )
  or
  
  // Case 4: Destructured parameters
  exists(Function f, Import imp |
    // GraphQL imports
    imp.getImportedPath().getValue().regexpMatch(".*(graphql|apollo).*") and
    imp.getFile() = f.getFile() and
    
    // Function has resolver signature
    f.getNumParameter() in [3, 4] and
    
    // First parameter is typically parent/root, check second parameter (the args position)
    exists(Parameter p |
      p = f.getParameter(1) and
      
      // No direct way to check for destructuring pattern, but we can check its string representation
      p.toString().matches("{%}") // Pattern like: {id, data}
    ) and
    
    // Source comes from within this function
    src.asExpr().getEnclosingFunction() = f and
    
    // Source is a variable reference that exists in destructuring scope
    exists(VarRef ref | 
      ref = src.asExpr() and
      ref.getVariable().getScope() = f.getScope() and
      // Not a parameter variable
      not exists(Parameter fp | fp.getAVariable() = ref.getVariable()) and
      // Common GraphQL field names
      ref.getVariable().getName() in ["id", "input", "data", "filter", "where", "variables"]
    )
  )
}

/* Client-Side & DOM Sources. */
// some might be covered by RemoteFlowSource, but we will include them for completeness.

// Detects client-side user input sources from DOM elements, events, and framework-specific patterns.
// This covers standard DOM APIs, jQuery, React, Angular, and other common patterns.
predicate isClientSideUserInputSource(DataFlow::Node src) {
  // Case 1: Direct property access to DOM elements
  exists(PropAccess acc |
    acc = src.asExpr() and
    
    // Properties that contain user input
    acc.getPropertyName() in [
      // Standard value properties
      "value", "innerText", "textContent", "innerHTML", 
      // Form control specific
      "checked", "selected", "selectedIndex", "selectedOptions", 
      // File input specific
      "files", "fileName",
      // Custom data attributes
      "dataset"
    ] and
    
    // Element types that accept user input
    (
      acc.getBase().getType().hasUnderlyingType("HTMLInputElement") or
      acc.getBase().getType().hasUnderlyingType("HTMLTextAreaElement") or
      acc.getBase().getType().hasUnderlyingType("HTMLSelectElement") or
      acc.getBase().getType().hasUnderlyingType("HTMLElement") or
      acc.getBase().getType().hasUnderlyingType("HTMLFormElement") or
      acc.getBase().getType().hasUnderlyingType("Element") or
      // Fallback for untyped cases with naming patterns
      exists(VarRef ref |
        ref = acc.getBase() and
        ref.getVariable().getName().regexpMatch("(?i).*(input|field|form|select|textarea|control|element).*")
      )
    )
  )
  or
  
  // Case 2: Method-based access to form values
  exists(MethodCallExpr call |
    call = src.asExpr() and
    
    // Common DOM API methods for accessing values
    (
      call.getMethodName() in ["getAttribute", "getAttributeNS"] and
      call.getArgument(0).mayHaveStringValue(["value", "data-value", "data-input", "data-content"]) 
    )
  )
  or
  
  // Case 3: jQuery-specific patterns
  exists(MethodCallExpr call |
    call = src.asExpr() and
    
    // jQuery method calls that access form values
    (
      call.getMethodName() in ["val", "text", "html"] and
      call.getNumArgument() = 0 and
      // Identify jQuery objects: $(...) or jQuery(...)
      exists(CallExpr jqCall | 
        jqCall = call.getReceiver() and
        (
          jqCall.getCalleeName() = "$" or
          jqCall.getCalleeName() = "jQuery"
        )
      )
    )
  )
  or
  
  // Case 4: Event objects in event handlers
  exists(Function f, Parameter p |
    // Event handler function
    (
      // Named with event handler pattern
      f.getName().regexpMatch("(?i).*(on|handle)(Change|Input|Submit|Click|KeyUp|KeyPress|MouseUp|MouseDown).*") or
      
      // Used as event listener
      exists(MethodCallExpr eventReg |
        eventReg.getMethodName() in ["addEventListener", "on"] and
        DataFlow::valueNode(eventReg.getArgument(1)).getAFunctionValue().getFunction() = f
      )
    ) and
    
    // First parameter is typically the event object
    p = f.getParameter(0) and
    
    // Access to event properties
    (
      // Direct target or value access
      exists(PropAccess acc |
        acc = src.asExpr() and
        (
          // event.target.value pattern
          exists(PropAccess targetAcc |
            acc.getBase() = targetAcc and
            targetAcc.getPropertyName() = "target" and
            targetAcc.getBase() = p.getAVariable().getAnAccess() and
            acc.getPropertyName() in ["value", "checked", "innerText", "innerHTML", "selectedOptions"]
          )
          or
          // event.value pattern (direct)
          acc.getBase() = p.getAVariable().getAnAccess() and
          acc.getPropertyName() in ["data", "value", "key", "clipboardData"]
        )
      )
      or
      // event.target reference that flows to a value access
      exists(PropAccess targetAcc, DataFlow::Node targetNode |
        targetAcc.getPropertyName() = "target" and
        targetAcc.getBase() = p.getAVariable().getAnAccess() and
        targetNode.asExpr() = targetAcc and
        
        // Used in a property access that is our source
        exists(PropAccess valueAcc |
          valueAcc = src.asExpr() and
          valueAcc.getBase() = targetNode.asExpr()
        )
      )
    )
  )
  or
  
  // Case 5: React state and refs holding user input
  exists(DataFlow::CallNode call, DataFlow::Node stateAccess |
    // useState hook pattern
    (
      call.getCalleeName() = "useState" and
      // Access to state value (first element of returned array)
      stateAccess.asExpr().(PropAccess).getPropertyName() = "0" and
      stateAccess.asExpr().(PropAccess).getBase() = call.getALocalUse().asExpr() and
      
      // The source is this state value
      src = stateAccess
    )
    or
    // useRef hook for form elements
    (
      call.getCalleeName() = "useRef" and
      // Access to ref.current.value pattern
      exists(PropAccess currentAcc, PropAccess valueAcc |
        currentAcc.getPropertyName() = "current" and
        currentAcc.getBase() = call.getALocalUse().asExpr() and
        
        valueAcc = src.asExpr() and
        valueAcc.getPropertyName() in ["value", "checked", "innerText", "files"] and
        valueAcc.getBase() = currentAcc
      )
    )
  )
  or
  
  // Case 6: Angular FormControl values
  exists(PropAccess acc, Variable v |
    acc = src.asExpr() and
    acc.getPropertyName() = "value" and
    acc.getBase() = v.getAnAccess() and
    v.getName().regexpMatch("(?i).*(form|control|input|field).*") and
    
    // Type check or method usage check for FormControl
    (
      exists(VarAccess varAcc | 
        varAcc = v.getAnAccess() and
        varAcc.getType().toString().matches("%FormControl%")
      ) or
      // Method usage check
      exists(MethodCallExpr mce |
        mce.getReceiver() = v.getAnAccess() and
        mce.getMethodName() in ["setValue", "patchValue", "reset", "updateValueAndValidity"]
      )
    )
  )
  or
  
  // Case 7: Generic framework patterns (Vue, other frameworks)
  exists(PropAccess acc |
    acc = src.asExpr() and
    // Common model/value property patterns
    acc.getPropertyName() in ["model", "modelValue", "inputValue", "fieldValue"] and
    
    // Context suggesting it's a form control (either by name or usage)
    exists(Variable v |
      v.getName().regexpMatch("(?i).*(input|field|form|control|model|value).*") and
      acc.getBase() = v.getAnAccess()
    )
  )
}

// Data stored in cookies, localStorage, or sessionStorage can be modified by the user.
predicate isClientStorageSource(DataFlow::Node src) {
  // Direct property access
  exists(PropAccess acc |
    acc = src.asExpr() and
    (
      // Document cookie
      (acc.getPropertyName() = "cookie" and acc.getBase().getType().hasUnderlyingType("Document")) or
      // Direct storage access
      acc.getPropertyName() in ["localStorage", "sessionStorage"] and acc.getBase().getType().hasUnderlyingType("Window")
    )
  )
  or
  // Storage API methods
  exists(MethodCallExpr call |
    call = src.asExpr() and
    call.getMethodName() = "getItem" and (
      // Direct calls on global objects
      call.getReceiver().(GlobalVarAccess).getName() in ["localStorage", "sessionStorage"] or
      // Calls on window.X
      exists(PropAccess prop | 
        prop = call.getReceiver() and
        prop.getPropertyName() in ["localStorage", "sessionStorage"] and
        prop.getBase().(GlobalVarAccess).getName() = "window"
      )
    )
  )
  or
  // Cookie parsing patterns
  exists(MethodCallExpr call, PropAccess cookieAccess |
    // Common cookie parsing patterns
    call = src.asExpr() and
    call.getMethodName() in ["split", "match", "substring"] and
    cookieAccess.getPropertyName() = "cookie" and
    cookieAccess.getBase().getType().hasUnderlyingType("Document") and
    call.getReceiver() = cookieAccess
  )
  or
  // IndexedDB
  exists(MethodCallExpr call, Variable dbVar |
    call = src.asExpr() and
    call.getMethodName() in ["get", "getAll"] and
    call.getReceiver() = dbVar.getAnAccess() and
    (
      // Variable has IndexedDB-related name
      dbVar.getName().matches(["%db%", "%store%", "%indexedDB%", "%idb%"]) or
      // Or variable is initialized from IndexedDB API
      exists(AssignExpr assign |
        assign.getLhs() = dbVar.getAnAccess() and
        assign.getRhs().(MethodCallExpr).getReceiver().toString().matches("%indexedDB%")
      )
    )
  )
}

// The URL and location-based data (e.g., query parameters, URL hash) can contain untrusted information
predicate isURLSource(DataFlow::Node src) {
  // Direct property access to Location/Window
  exists(PropAccess acc |
    acc = src.asExpr() and
    acc.getPropertyName() in ["href", "search", "hash", "pathname", "hostname", "protocol", "origin", "name"] and
    (
      acc.getBase().getType().hasUnderlyingType("Location") or
      acc.getBase().getType().hasUnderlyingType("Window") or
      acc.getBase().(GlobalVarAccess).getName() = "location" or
      acc.getBase().(PropAccess).getPropertyName() = "location"
    )
  )
  or
  // URLSearchParams API
  exists(DataFlow::NewNode newUrl |
    newUrl.getCalleeName() = "URLSearchParams" and
    (
      // Direct access to URLSearchParams object
      src = newUrl or
      // Method calls on URLSearchParams
      exists(MethodCallExpr call |
        call = src.asExpr() and
        call.getMethodName() in ["get", "getAll", "has", "entries", "forEach", "keys", "values"] and
        call.getReceiver() = newUrl.asExpr()
      )
    )
  )
  or
  // URL constructor
  exists(DataFlow::NewNode newUrl |
    newUrl.getCalleeName() = "URL" and
    (
      // Property access on URL object
      exists(PropAccess acc |
        acc = src.asExpr() and
        acc.getBase() = newUrl.asExpr() and
        acc.getPropertyName() in ["search", "hash", "searchParams", "pathname", "href"]
      )
    )
  )
  or
  // Framework-specific patterns (React Router, etc.)
  exists(CallExpr call |
    call = src.asExpr().getParent*() and
    call.getCalleeName() in ["useLocation", "useParams", "useSearchParams", "getParam"] and
    (
      // Direct usage of hook result
      src.asExpr() = call or
      // Access to properties of hook result
      exists(PropAccess acc |
        acc = src.asExpr() and
        acc.getBase() = call and
        acc.getPropertyName() in ["search", "pathname", "hash", "state", "query", "params"]
      )
    )
  )
}

// Detects tainted data from postMessage-based communication.
predicate isPostMessageSource(DataFlow::Node src) {
  // Case 1: addEventListener with message event
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "addEventListener" and
    call.getArgument(0).mayHaveStringValue("message") and
    
    exists(DataFlow::FunctionNode callback, DataFlow::ParameterNode event, DataFlow::PropRead dataAccess |
      callback = call.getArgument(1).getAFunctionValue() and
      event.getParameter() = callback.getFunction().getParameter(0) and
      dataAccess = event.getAPropertyRead("data") and
      dataAccess = src
    )
  )
  or
  // Case 2: onmessage property assignments
  exists(DataFlow::PropWrite propWrite, DataFlow::FunctionNode callback, DataFlow::ParameterNode event, DataFlow::PropRead dataAccess |
    propWrite.getPropertyName() = "onmessage" and
    callback = propWrite.getRhs().getAFunctionValue() and
    event.getParameter() = callback.getFunction().getParameter(0) and
    dataAccess = event.getAPropertyRead("data") and
    dataAccess = src
  )
  or
  // Case 3: nested property access from event.data
  exists(DataFlow::Node eventData, DataFlow::PropRead nestedAccess |
    isEventDataAccess(eventData) and
    nestedAccess.getBase() = eventData and
    nestedAccess = src
  )
  or
    // Case 4: variable assignment from event.data
    exists(DataFlow::Node eventData, AssignExpr assign, DataFlow::Node lhs |
      isEventDataAccess(eventData) and
      assign.getRhs() = eventData.asExpr() and
      lhs.asExpr() = assign.getLhs() and
      lhs = src
    )
}

// Helper predicate to identify event.data access in message event handlers
private predicate isEventDataAccess(DataFlow::Node node) {
  exists(DataFlow::FunctionNode messageHandler, DataFlow::ParameterNode event |
    // Find message event handler functions
    (
      // Via addEventListener
      exists(DataFlow::MethodCallNode call |
        call.getMethodName() = "addEventListener" and
        call.getArgument(0).mayHaveStringValue("message") and
        messageHandler = call.getArgument(1).getAFunctionValue()
      )
      or
      // Via onmessage property
      exists(DataFlow::PropWrite propWrite |
        propWrite.getPropertyName() = "onmessage" and
        messageHandler = propWrite.getRhs().getAFunctionValue()
      )
    ) and
    // Get the event parameter
    event.getParameter() = messageHandler.getFunction().getParameter(0) and
    // Access to event.data
    node = event.getAPropertyRead("data")
  )
}

 /* -- Environment variables and command-line inputs -- */
 // Access to process.env.X environment variables, process.stdin, and process.argv[X] command-line arguments
 // are considered taint sources (untrusted data).
class ProcessSource extends DataFlow::SourceNode {
  ProcessSource() {
    // direct property access
    this = any(
      DataFlow::globalVarRef("process").
      getAPropertyRead(["env","argv", "stdin"]).
      getAPropertyReference()
    )
    or
    // Handle destructuring patterns
    exists(VariableDeclarator decl, DataFlow::PropRead processEnv, VarRef ref |
      processEnv = DataFlow::globalVarRef("process").getAPropertyRead("env") and
      decl.getInit() = processEnv.asExpr() and
      decl.getBindingPattern() instanceof DestructuringPattern and
      ref = decl.getBindingPattern().getABindingVarRef() and
      this = DataFlow::valueNode(ref)
    )
    or
    // Handle variable assignments
    exists(AssignExpr assign, DataFlow::PropRead propRead |
      propRead = DataFlow::globalVarRef("process").getAPropertyRead(["env", "argv", "stdin"]) and
      propRead.asExpr() = assign.getRhs() and
      this = DataFlow::valueNode(assign.getLhs())
    )
    or
    // Common process methods that provide system info
    this = DataFlow::globalVarRef("process").getAMethodCall(["cwd", "getuid", "getgid", "getgroups", "getPid"])
  }
}

 /* -- File system read sources -- */
 // File system read sources are considered taint sources (untrusted data).
 predicate isFsReadCall(DataFlow::CallNode call) {
  exists(DataFlow::CallNode c |
    (
      c = DataFlow::moduleMember("fs", _).getACall() and
      c.getCalleeName() = ["readFile", "readFileSync", "readSync", "createReadStream"]
    )
    |
    call = c
  )
}

 from DataFlow::Node src, string description
 where isRemoteSource(src) and description = "Remote/user input source" or
        isHeuristicHttpRequestSource(src) and description = "HTTP request source" or
        isGraphQLRequestSource(src) and description = "GraphQL request source" or
        isClientSideUserInputSource(src) and description = "Client-side source" or
        isClientStorageSource(src) and description = "Client storage source" or
        isURLSource(src) and description = "URL source" or
        isPostMessageSource(src) and description = "postMessage source" or
       src instanceof ProcessSource and description = "Environment variable or command-line input source" or
       isFsReadCall(src) and description = "File read source"
 select src.asExpr(), description, src.getLocation()