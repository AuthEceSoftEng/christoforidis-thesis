/**
 * @name All Potential Vulnerability Sinks in JavaScript
 * @description Identifies a broad range of potential vulnerability sinks, including command execution, database queries, file operations, and more.
 * @kind table
 * @id js/all-possible-sinks
 * @tags inventory
 *       sinks
 */

import javascript
import isSink
import helpers

// Main query
from DataFlow::Node sink, int contextStartLine, int contextEndLine
where 
  getSinkCategory(sink) != "Unknown sink" and
  getContextLineRange(sink, contextStartLine, contextEndLine) and
  not isTestFile(sink.getFile())
select 
  sink.asExpr() as expression,
  getSinkCategory(sink) as category,
  sink.getLocation().getFile().getAbsolutePath() as location,
  sink.getLocation().getStartLine() as startLine,
  sink.getLocation().getStartColumn() as startColumn,
  contextStartLine as contextStart,
  contextEndLine as contextEnd