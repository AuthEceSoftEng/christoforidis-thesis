/**
 * @name External Dependency Method Calls
 * @description Extracts method calls from package.json dependencies
 * @kind table
 * @id js/dependency-methods
 */

 import javascript
 import semmle.javascript.dependencies.Dependencies
 import isTestFile
 
 from 
   DataFlow::CallNode call,
   ExternalNpmDependency dependency,
   Import imp,
   string methodName
 where 
   // Get an import that refers to this dependency
   imp = dependency.getAnImport() and
   
   // Match the imported path
   exists(string path | 
     path = imp.getImportedPath().getValue() and
     
     // Handle direct calls on imports
     (
       // Regular method calls
       DataFlow::moduleMember(path, _).getACall() = call or
       
       // Direct calls on the module
       DataFlow::moduleImport(path).getACall() = call or
       
       // Track through variable assignments and references
       exists(DataFlow::SourceNode src, DataFlow::SourceNode tracked |
         (
           src = DataFlow::moduleImport(path) or
           src = DataFlow::moduleMember(path, _)
         ) and
         tracked = src.getALocalSource() and
         call = tracked.getAMethodCall()
       )
     )
   ) and
   
   // Get method name - handle both property reads and direct calls
   (
     exists(DataFlow::PropRead propRead |
       propRead = call.getCalleeNode() and
       methodName = propRead.getPropertyName()
     ) or
     methodName = call.getCalleeName()
   ) and

   // exclude test files
    not isTestFile(call.getFile())
 
 select
   dependency.getNpmPackageName() as packageName,
   dependency.getVersion() as version,
   methodName