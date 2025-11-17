/**
 * helper functions/predicates/classed for codeql queries
 */

 import javascript
 // Gets the line range for a node's context to avoid string truncation
predicate getContextLineRange(DataFlow::Node node, int startLine, int endLine) {
  // Special case for WebSocket handler parameters
  exists(DataFlow::MethodCallNode call, DataFlow::FunctionNode callback, Parameter param |
    call.getMethodName() in ["on", "once", "addListener"] and
    callback = call.getArgument(1).getAFunctionValue() and
    param = callback.getFunction().getParameter(0) and
    DataFlow::parameterNode(param) = node and
    startLine = call.getLocation().getStartLine() and
    endLine = call.getLocation().getEndLine()
  )
  or
  // Use statement contexts but just return line numbers
  exists(Expr e | e = node.asExpr() |
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
  // Fallback: use the node's own location
  (
    not exists(Expr e | e = node.asExpr()) or
    not exists(Stmt stmt | stmt = node.asExpr().getEnclosingStmt())
  ) and
  startLine = node.getLocation().getStartLine() - 5 and
  endLine = node.getLocation().getStartLine() + 5  // Add a small buffer
}

// Holds if the file is a test file based on common naming conventions
 predicate isTestFile(File file) {
   exists(string path | path = file.getAbsolutePath() |
     // Common test directories
     path.matches("%/test/%") or
     path.matches("%/tests/%") or
     path.matches("%/__tests__/%") or
     path.matches("%/__mocks__/%") or
     path.matches("%/cypress/%") or
     
     // JavaScript test files
     path.matches("%spec.js") or
     path.matches("%test.js") or
     path.matches("%cy.js") or
     
     // TypeScript test files
     path.matches("%spec.ts") or
     path.matches("%test.ts") or
     path.matches("%cy.ts") or
     path.matches("%spec.tsx") or
     path.matches("%test.tsx") or
     
     // Additional TypeScript-specific test patterns
     path.matches("%e2e.ts") or
     path.matches("%fixture.ts") or
     path.matches("%mock.ts")
   )
 }