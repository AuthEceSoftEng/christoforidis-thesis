/**
 * @name Call Graph Extraction
 * @description Extract function call relationships for understanding data flow architecture
 * @kind table
 * @id js/call-graph-extraction
 */

import javascript
import DataFlow

from DataFlow::InvokeNode call, Function caller
where 
  caller = call.getEnclosingExpr().getEnclosingFunction() and
  not caller.getFile().getAbsolutePath().matches("%node_modules%")
select 
  caller.getFile().getRelativePath() as caller_file,
  caller.getName() as caller_name,
  call.getCalleeName() as call_name,
  call.getStartLine() as line