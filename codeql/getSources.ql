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
 import isTestFile

 /* -- Source categories as predicates or classes -- */
 
 /* - Remote/user input sources -  */

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

// Detects data returned from Fetch API and HTTP client libraries, which may contain untrusted content.
// Covers both native fetch API and popular libraries like axios, superagent, etc.
predicate isFetchResponseSource(DataFlow::Node src) {
  // Case 1: Direct fetch response object methods
  exists(DataFlow::MethodCallNode methodCall, DataFlow::Node responseObject |
    isFetchResponse(responseObject) and
    methodCall.getReceiver() = responseObject and
    methodCall.getMethodName() in ["json", "text", "blob", "formData", "arrayBuffer"] and
    src = methodCall
  )
  or
  // Case 2: Parsed fetch response data
  exists(DataFlow::MethodCallNode jsonMethod, Variable responseJsonVar |
    // Find the response.json() method call
    jsonMethod.getMethodName() = "json" and
    isFetchResponse(jsonMethod.getReceiver()) and
    
    // Find where it's assigned to a variable
    exists(VariableDeclarator decl |
      decl.getInit() = jsonMethod.asExpr() or
      decl.getInit().(AwaitExpr).getOperand() = jsonMethod.asExpr() and
      responseJsonVar = decl.getBindingPattern().getAVariable()
    ) and
    
    // Track access to the parsed JSON
    exists(PropAccess acc |
      acc.getBase() = responseJsonVar.getAnAccess() and
      src = DataFlow::valueNode(acc)
    )
  )
  or
  // Case 3: HTTP client libraries with promise-based APIs
  exists(DataFlow::ModuleImportNode client, DataFlow::CallNode request, DataFlow::MethodCallNode thenCall,
         DataFlow::FunctionNode callback, string clientName |
    // Common HTTP client libraries
    clientName in ["axios", "superagent", "request-promise", "got", "node-fetch", "ky", "needle"] and
    client.getPath() = clientName and
    
    // Handle library-specific request calls
    (
      // Direct client call: axios(url), request(url)
      request = client.getACall() or
      // Method call: axios.get(), axios.post()
      request = client.getAMemberCall(["get", "post", "put", "delete", "patch", "head"])
    ) and
    
    // Promise chain
    thenCall.getMethodName() = "then" and
    thenCall.getReceiver() = request and
    callback = thenCall.getArgument(0).getAFunctionValue() and
    
    // Different libraries have different response structures
    (
      // Direct response parameter
      src = callback.getParameter(0) or
      
      // Library-specific response property patterns
      exists(DataFlow::PropRead dataProp |
        dataProp.getBase() = callback.getParameter(0) and
        dataProp.getPropertyName() in ["data", "body", "responseText", "json"] and
        src = dataProp
      )
    )
  )
  or
  // Case 4: HTTP client libraries with async/await
  exists(DataFlow::ModuleImportNode client, DataFlow::CallNode request, 
         AwaitExpr awaitExpr, Variable responseVar, string clientName |
    // Common HTTP client libraries
    clientName in ["axios", "superagent", "request-promise", "got", "node-fetch", "ky"] and
    client.getPath() = clientName and
    
    // Handle library-specific request calls
    (
      // Direct client call: await axios(url)
      request = client.getACall() or
      // Method call: await axios.get()
      request = client.getAMemberCall(["get", "post", "put", "delete", "patch", "head"])
    ) and
    
    // Await the request
    awaitExpr.getOperand() = request.asExpr() and
    
    // Store in variable
    exists(VariableDeclarator decl |
      decl.getInit() = awaitExpr and
      responseVar = decl.getBindingPattern().getAVariable()
    ) and
    
    // Access the response data
    (
      // Direct response variable
      src.asExpr() = responseVar.getAnAccess() or
      
      // Library-specific response property access
      exists(PropAccess acc |
        acc.getBase() = responseVar.getAnAccess() and
        acc.getPropertyName() in ["data", "body", "responseText", "json"] and
        src.asExpr() = acc
      )
    )
  )
  or
  // Case 5: Callback-based HTTP clients
  exists(DataFlow::ModuleImportNode client, DataFlow::CallNode request, 
         DataFlow::FunctionNode callback, string clientName |
    clientName in ["request", "superagent", "needle", "http", "https"] and
    client.getPath() = clientName and
    
    (
      // Direct request with callback
      request = client.getACall() or
      // Method with callback
      request = client.getAMemberCall(["get", "post", "put", "delete"])
    ) and
    
    // Last argument is callback function
    callback = request.getLastArgument().getAFunctionValue() and
    
    (
      // Common callback patterns: (err, response, body) => { ... }
      src = callback.getParameter([1, 2]) or
      
      // Response property access in callback
      exists(DataFlow::PropRead propRead |
        propRead.getBase() = callback.getParameter(1) and
        propRead.getPropertyName() in ["body", "data"] and
        src = propRead
      )
    )
  )
}

// Helper to identify fetch response objects
private predicate isFetchResponse(DataFlow::Node node) {
  // From fetch().then(response => ...)
  exists(DataFlow::CallNode fetchCall, DataFlow::MethodCallNode thenCall, DataFlow::FunctionNode callback |
    fetchCall.getCalleeNode().toString() = "fetch" and
    thenCall.getMethodName() = "then" and
    thenCall.getReceiver() = fetchCall and
    callback = thenCall.getArgument(0).getAFunctionValue() and
    node = callback.getParameter(0)
  )
  or
  // From async/await: const response = await fetch()
  exists(DataFlow::CallNode fetchCall, AwaitExpr awaitExpr, VariableDeclarator decl |
    fetchCall.getCalleeNode().toString() = "fetch" and
    awaitExpr.getOperand() = fetchCall.asExpr() and
    decl.getInit() = awaitExpr and
    node = DataFlow::valueNode(decl.getBindingPattern().getAVariable().getAnAccess())
  )
}

// Detects untrusted data received through WebSocket connections and similar socket-based communication.
// Covers both standard WebSocket API (onmessage) and popular libraries like Socket.IO (on/once methods).
predicate isWebSocketSource(DataFlow::Node src) {
  // Case 1: socket.on/once with data events
  exists(DataFlow::MethodCallNode call, DataFlow::FunctionNode callback |
    // Common WebSocket methods
    (call.getMethodName() = "on" or call.getMethodName() = "once" or call.getMethodName() = "addListener") and
    
    // Match data-carrying events (not connection events)
    not call.getArgument(0).mayHaveStringValue(["connect", "disconnect", "error", "connection", "close"]) and
    
    // Function callback
    callback = call.getArgument(1).getAFunctionValue() and
    
    // Either parameter itself or property access from parameter
    (
      src = callback.getParameter(0) or
      exists(DataFlow::PropRead propRead |
        propRead.getBase() = callback.getParameter(0) and // Removed getANode()
        propRead = src
      )
    ) and
    
    // WebSocket object detection
    (
      exists(DataFlow::NewNode newCall |
        newCall.getCalleeName() in ["WebSocket", "SockJS", "Socket"] and
        call.getReceiver().getALocalSource() = newCall
      ) or
      call.getReceiver().toString().regexpMatch("(?i)(^|\\W)(socket|io|ws)(\\W|$)")
    )
  )
  or
  // Case 2: Traditional WebSocket onmessage
  exists(DataFlow::PropWrite propWrite, DataFlow::FunctionNode callback |
    propWrite.getPropertyName() in ["onmessage", "ondata"] and
    callback = propWrite.getRhs().getAFunctionValue() and
    exists(DataFlow::PropRead eventData |
      eventData.getBase() = callback.getParameter(0) and // Removed getANode()
      eventData.getPropertyName() = "data" and
      eventData = src
    ) and
    propWrite.getBase().toString().regexpMatch("(?i).*(socket|ws|websocket).*")
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
    
    // Improved resolver identification heuristics
    (
      // Within a resolver object map (most common case - keep this as is)
      exists(ObjectExpr obj |
        obj.getPropertyByName(["Query", "Mutation", "Subscription"]).getInit() = f or
        obj.getPropertyByName(["Query", "Mutation", "Subscription"]).getInit()
          .(ObjectExpr).getAProperty().getInit() = f
      )
      or
      // More specific function naming patterns that reduce false positives
      (
        // Must start with or end with specific resolver terms
        f.getName().regexpMatch("^(resolve|query|get|fetch)[A-Z].*") or
        f.getName().regexpMatch(".*Resolver$") or
        f.getName().regexpMatch("^(create|update|delete)[A-Z].*Mutation$") or
        f.getName().regexpMatch("^(subscribe|watch|on)[A-Z].*Subscription$") or
        
        // Exact matches for common resolver naming patterns
        f.getName() in [
          "resolve", "resolver", "queryResolver", "mutationResolver", "subscriptionResolver"
        ]
      )
      or
      // Default case: stricter parameter pattern + additional evidence
      (
        // Standard resolver parameter pattern
        f.getParameter(0).getName() in ["parent", "root", "_", "obj", "source"] and
        f.getParameter(1).getName() in ["args", "arg", "arguments"] and
        f.getParameter(2).getName() in ["context", "ctx", "contextValue"] and
        
        // Additional evidence: file has resolver-related naming or type definitions
        (
          f.getFile().getBaseName().regexpMatch(".*(resolver|schema|graphql|apollo).*\\.(js|ts)$") or
          exists(ObjectExpr obj | 
            obj.getFile() = f.getFile() and 
            obj.getPropertyByName(["typeDefs", "resolvers", "schema"]).getInit() instanceof ObjectExpr
          )
        )
      )
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
    
    // Function has resolver pattern and exists in a resolver context
    f.getNumParameter() in [3, 4] and
    (
      // Within a resolver object map
      exists(ObjectExpr obj |
        obj.getPropertyByName(["Query", "Mutation", "Subscription"]).getInit() = f or
        obj.getPropertyByName(["Query", "Mutation", "Subscription"]).getInit()
          .(ObjectExpr).getAProperty().getInit() = f
      )
      or
      // File has resolver-related naming
      f.getFile().getBaseName().regexpMatch(".*(resolver|schema).*\\.(js|ts)$")
    )
  )
  or
  
  // Case 3: Variables derived from resolver parameters
  exists(Variable v, Function f, VariableDeclarator decl, Import imp |
    // Source is a property access on this variable
    exists(PropAccess pa |
      pa = src.asExpr() and
      pa.getBase() = v.getAnAccess()
    ) and
    
    // GraphQL context verification
    imp.getImportedPath().getValue().regexpMatch(".*(graphql|apollo).*") and
    imp.getFile() = f.getFile() and
    
    // The variable was declared and initialized from a parameter
    decl.getBindingPattern().getAVariable() = v and 
    decl.getInit() = f.getParameter(1).getAVariable().getAnAccess() and
    f.getParameter(1).getName() in ["args", "arg", "arguments"] and
    
    // In the same function
    decl.getContainer() = f and    
    f.getNumParameter() in [3, 4] and
    
    // Additional resolver context evidence
    (
      // Within a resolver object structure
      exists(ObjectExpr obj |
        obj.getPropertyByName(["Query", "Mutation", "Subscription"]).getInit() = f or
        obj.getPropertyByName(["Query", "Mutation", "Subscription"]).getInit()
          .(ObjectExpr).getAProperty().getInit() = f
      )
      or
      // Function name matches resolver pattern
      f.getName().regexpMatch("^(resolve|query|get|create|update|delete)[A-Z].*") or
      f.getName().regexpMatch(".*Resolver$")
    )
  )
}

/* Client-Side & DOM Sources. */
// some might be covered by RemoteFlowSource, but we will include them for completeness.

// Detects client-side user input sources from DOM elements, events, and framework-specific patterns.
// This covers standard DOM APIs, jQuery, React, Angular, and other common patterns.
predicate isClientSideUserInputSource(DataFlow::Node src) {
  // Case 1: Direct property access to DOM elements - ONLY WHEN READING
  exists(PropAccess acc |
    acc = src.asExpr() and
    
    // Properties that contain user input
    acc.getPropertyName() in [
      "value", "innerText", "textContent", "innerHTML", "checked", "selected", 
      "selectedIndex", "selectedOptions", "files"
    ] and
    
    // ONLY CONSIDER READS, NOT WRITES
    not exists(AssignExpr assign | assign.getLhs() = acc) and
    
    (
      // Strong type evidence - must have proper DOM type
      acc.getBase().getType().hasUnderlyingType("HTMLInputElement") or
      acc.getBase().getType().hasUnderlyingType("HTMLTextAreaElement") or
      acc.getBase().getType().hasUnderlyingType("HTMLSelectElement") or
      acc.getBase().getType().hasUnderlyingType("HTMLFormElement") or
      
      // DOM element retrieval context
      exists(MethodCallExpr domMethod, Variable v |
        // Element retrieved using DOM methods
        domMethod.getMethodName() in [
          "getElementById", "querySelector", "getElementsByTagName", 
          "getElementsByClassName", "getElementsByName"
        ] and
        exists(VariableDeclarator decl |
          decl.getBindingPattern().getAVariable() = v and
          decl.getInit() = domMethod
        ) and
        // And property access is on this variable
        acc.getBase() = v.getAnAccess()
      )
      or
      // Restricted name-based matching with word boundaries
      exists(string pattern |
        pattern = "(?i)(^|\\W)(input|textarea|select|checkbox|form|button|control)(\\W|$)" and
        acc.getBase().toString().regexpMatch(pattern)
      ) and
      // Plus additional DOM context evidence
      exists(Stmt stmt |
        stmt = acc.getEnclosingStmt() and
        (
          // In a function with event handler naming
          stmt.getContainer().(Function).getName().regexpMatch("(?i)(^|\\W)(on|handle)(Submit|Change|Input|Click)(\\W|$)") or
          
          // In a file with form processing context
          exists(Expr formExpr |
            formExpr.getFile() = acc.getFile() and
            (
              exists(MethodCallExpr formMethod |
                formMethod.getMethodName() in ["preventDefault", "stopPropagation", "submit", "validate", "serialize"] and
                formMethod = formExpr
              ) or
              exists(PropAccess formProp |
                formProp.getPropertyName() in ["elements", "length", "action", "method", "target"] and
                formProp.getBase().getType().hasUnderlyingType("HTMLFormElement")
              )
            )
          )
        )
      )
    )
  )
  or
  
  // Case 2: Event handler pattern with explicit event.target.value/responseText access
  exists(Function f, Parameter p, PropAccess valueAcc, PropAccess targetAcc |
    // Must be in an event handler function
    (
      // event handler function name pattern with word boundaries
      f.getName().regexpMatch("(?i)(^|\\W)(on|handle)(Change|Input|Submit|Click)(\\W|$)") or
      
      // Explicit event registration
      exists(MethodCallExpr eventReg |
        eventReg.getMethodName() = "addEventListener" and
        eventReg.getArgument(0).mayHaveStringValue(["input", "change", "submit", "click"]) and
        eventReg.getArgument(1) = DataFlow::valueNode(f).(DataFlow::FunctionNode).getFunction()
      )
    ) and
    
    // First parameter is event object
    p = f.getParameter(0) and
    
    // event.target.X pattern
    valueAcc = src.asExpr() and
    valueAcc.getPropertyName() in ["value", "checked", "selectedOptions", "files"] and
    valueAcc.getBase() = targetAcc and
    targetAcc.getPropertyName() = "target" and
    targetAcc.getBase() = p.getAVariable().getAnAccess()
  )
  or
  
  // Case 3: jQuery val() method with zero arguments (getter mode)
  exists(MethodCallExpr call |
    call = src.asExpr() and
    call.getMethodName() = "val" and
    call.getNumArgument() = 0 and
    (
      // Ensure it's actually jQuery
      exists(CallExpr jqCall | 
        jqCall = call.getReceiver() and
        jqCall.getCalleeName() = "$"
      ) or
      // Or explicitly jQuery object
      call.getReceiver().getType().toString().matches("%jQuery%")
    )
  )
  
  or
  
  // Case 4: XMLHttpRequest response/responseText
  exists(PropAccess acc |
    acc = src.asExpr() and
    acc.getPropertyName() in ["responseText", "response", "responseXML"] and
    (
      acc.getBase().getType().hasUnderlyingType("XMLHttpRequest") or
      acc.getBase().(VarRef).getVariable().getAnAssignedExpr().(NewExpr).getCalleeName() = "XMLHttpRequest"
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
    // Focus on security-sensitive environment variables
    exists(string envVarName, DataFlow::PropRead envVar |
      envVar = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyRead() and
      envVarName = envVar.getPropertyName() and
      (
        // HIGH RISK: Security-critical patterns
        envVarName.regexpMatch("(?i).*(SECRET|KEY|TOKEN|PASS|AUTH|PWD|CREDENTIAL).*") or
        
        // MEDIUM RISK: Configuration endpoints and connection strings
        envVarName.regexpMatch("(?i).*(URL|ENDPOINT|API|WEBHOOK).*") or
        
        // LOW RISK but still included: Other variables except common safe ones
        not (
          envVarName in ["NODE_ENV", "PORT", "HOST", "DEBUG", "LOG_LEVEL", "ENV", "ENVIRONMENT"] or
          // Filter out system information variables
          envVarName.regexpMatch("(?i).*(PATH|HOME|USER|DIR|VERSION|ARCH|OS|TYPE|TEMP|TMP).*")
        )
      ) and
      this = envVar
    )
    or
    // Only include command line args beyond the standard ones (which are rarely attack vectors)
    exists(DataFlow::PropRead argvRead, DataFlow::PropRead indexExpr, int index |
      argvRead = DataFlow::globalVarRef("process").getAPropertyRead("argv") and
      indexExpr = argvRead.getAPropertyRead() and
      index = indexExpr.getPropertyName().toInt() and
      // Skip standard args (0=node path, 1=script path)
      not index in [0, 1] and
      this = indexExpr
    )
    or
    // process.stdin is always external input
    this = DataFlow::globalVarRef("process").getAPropertyRead("stdin")
  }
}

 /* -- File system read sources -- */
 // File system read sources are considered taint sources (untrusted data).
 predicate isFsReadCall(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    call = node and (
      // Standard fs module
      exists(DataFlow::ModuleImportNode fs |
        fs.getPath() = "fs" and
        (
          // Direct synchronous/async methods that read external content
          call = fs.getAMemberCall(["readFile", "readFileSync", "createReadStream"]) or
          
          // Promise-based methods
          exists(DataFlow::PropRead promises |
            promises = fs.getAPropertyRead("promises") and
            call = promises.getAMemberCall("readFile")
          )
        )
      )
      or
      // Popular third-party fs modules (more focused)
      exists(DataFlow::ModuleImportNode fsModule |
        fsModule.getPath() in ["fs-extra", "graceful-fs", "mz/fs"] and
        call = fsModule.getAMemberCall(["readFile", "readFileSync", "createReadStream"])
      )
      or
      // File parsers - focus on actual parsing methods
      exists(DataFlow::ModuleImportNode parser |
        parser.getPath() in ["csv-parser", "xml2js", "yaml", "ini", "properties-reader", "toml"] and
        (
          call = parser.getACall() or
          call = parser.getAMemberCall(["parse", "load", "parseFile", "loadFile"])
        )
      )
      or
      // Improved custom wrapper pattern detection
      exists(Function readFileWrapper |
        // More specific function name patterns
        (
          // Must start with read/load/parse + "File"
          readFileWrapper.getName().regexpMatch("^(?i)(read|load|parse|import)File[A-Z0-9_].*") or
          
          // Or exact matches for common patterns
          readFileWrapper.getName() in ["readFile", "loadFile", "parseFile", "readFileContent"]
        ) and
        
        // Require fs-related imports in the same file
        exists(Import imp |
          imp.getFile() = readFileWrapper.getFile() and
          imp.getImportedPath().getValue() in ["fs", "fs-extra", "graceful-fs", "path"] 
        ) and
        
        exists(DataFlow::FunctionNode fn |
          fn.getFunction() = readFileWrapper and 
          call = fn.getACall()
        )
      )
    )
  )
}

string getSourceCategory(DataFlow::Node src) {
  if isRemoteSource(src) then result = "Remote/user input"
  else if isHeuristicHttpRequestSource(src) then result = "HTTP request"
  else if isFetchResponseSource(src) then result = "Fetch response"
  else if isWebSocketSource(src) then result = "WebSocket"
  else if isGraphQLRequestSource(src) then result = "GraphQL request"
  else if isClientSideUserInputSource(src) then result = "Client-side"
  else if isClientStorageSource(src) then result = "Client storage"
  else if isURLSource(src) then result = "URL source"
  else if isPostMessageSource(src) then result = "postMessage source"
  else if isFsReadCall(src) then result = "File read"
  else if src instanceof ProcessSource then result = "Env variable/command-line input"
  else result = "Unknown source" // Default case
}

// Gets the line range for a source's context to avoid string truncation
predicate getContextLineRange(DataFlow::Node src, int startLine, int endLine) {
  // Special case for WebSocket handler parameters
  exists(DataFlow::MethodCallNode call, DataFlow::FunctionNode callback, Parameter param |
    call.getMethodName() in ["on", "once", "addListener"] and
    callback = call.getArgument(1).getAFunctionValue() and
    param = callback.getFunction().getParameter(0) and
    DataFlow::parameterNode(param) = src and
    startLine = call.getLocation().getStartLine() and
    endLine = call.getLocation().getEndLine()
  )
  or
  // Use statement contexts but just return line numbers
  exists(Expr e | e = src.asExpr() |
    exists(Stmt stmt | stmt = e.getEnclosingStmt() |
      exists(Stmt contextStmt |
        // Find the most appropriate context statement
        (
          contextStmt = stmt.getParent() or  // Parent statement
          contextStmt = stmt.getContainer().(Function).getBody() or // Function body
          contextStmt = stmt // Statement itself
        ) and
        startLine = contextStmt.getLocation().getStartLine() and
        endLine = contextStmt.getLocation().getEndLine()
      )
    )
  )
  or
  // Fallback: use the source's own location
  (
    not exists(Expr e | e = src.asExpr()) or
    not exists(Stmt stmt | stmt = src.asExpr().getEnclosingStmt())
  ) and
  startLine = src.getLocation().getStartLine() - 5 and
  endLine = src.getLocation().getStartLine() + 5  // Add a small buffer
}

// Main query
from DataFlow::Node src, int contextStartLine, int contextEndLine
where 
  getSourceCategory(src) != "Unknown source" and
  getContextLineRange(src, contextStartLine, contextEndLine) and
  not isTestFile(src.getFile())
select 
  src.asExpr() as expression,
  getSourceCategory(src) as category,
  src.getLocation().getFile().getAbsolutePath() as location, // Full file path for post-processing
  src.getLocation().getStartLine() as startLine,
  src.getLocation().getStartColumn() as startColumn,
  contextStartLine as contextStart,
  contextEndLine as contextEnd

/* 
from DataFlow::Node src
where getSourceCategory(src) != "Unknown source"
select src.asExpr(), getSourceCategory(src), src.getLocation()
 */