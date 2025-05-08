/**
 * Provides utilities for identifying test files
 */

 import javascript

 /**
  * Holds if the file is a test file based on common naming conventions
  */
 predicate isTestFile(File file) {
   exists(string path | path = file.getAbsolutePath() |
     // Common test directories
     path.matches("%/test/%") or
     path.matches("%/tests/%") or
     path.matches("%/__tests__/%") or
     path.matches("%/__mocks__/%") or
     path.matches("%/cypress/%") or
     
     // JavaScript test files
     path.matches("%.spec.js") or
     path.matches("%.test.js") or
     path.matches("%.cy.js") or
     
     // TypeScript test files
     path.matches("%.spec.ts") or
     path.matches("%.test.ts") or
     path.matches("%.cy.ts") or
     path.matches("%.spec.tsx") or
     path.matches("%.test.tsx") or
     
     // Additional TypeScript-specific test patterns
     path.matches("%.e2e.ts") or
     path.matches("%.fixture.ts") or
     path.matches("%.mock.ts")
   )
 }