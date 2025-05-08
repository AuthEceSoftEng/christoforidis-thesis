/**
 * @name External Dependency Method Calls
 * @description Extracts method calls from package.json dependencies
 * @kind table
 * @id js/dependency-methods
 */

 import javascript
 import semmle.javascript.dependencies.Dependencies
 
 from 
   CallExpr call, 
   ExternalNpmDependency dependency,
   Import imp,
   string methodName
 where 
   // Get an import that refers to this dependency
   imp = dependency.getAnImport() and
   
   // Link to the actual call via DataFlow
   exists(DataFlow::ModuleImportNode mymodule |
     mymodule.getPath() = imp.getImportedPath().getValue() and
     DataFlow::moduleImport(mymodule.getPath()).flowsToExpr(call.getCallee())
   ) and
   
   // Get method name
   methodName = call.getCalleeName()
   
   select
    dependency.getNpmPackageName() as packageName,
    dependency.getVersion() as version, 
    methodName as methodCalled