/**
 * @name All Potential Vulnerability Sources in JavaScript
 * @description Identifies a broad range of untrusted or external data sources, including user input, environment variables, file reads....
 * @kind table
 * @id js/all-possible-sources
 * @tags inventory
 *       sources
 */

 import javascript
 import isSource
 import helpers

// Main query
from DataFlow::Node src, int contextStartLine, int contextEndLine
where 
  getSourceCategory(src) != "Unknown source" and
  getContextLineRange(src, contextStartLine, contextEndLine) and
  not isTestFile(src.getFile())
select 
  src.asExpr() as expression,
  getSourceCategory(src) as category,
  src.getLocation().getFile().getAbsolutePath() as location,
  src.getLocation().getStartLine() as startLine,
  src.getLocation().getStartColumn() as startColumn,
  contextStartLine as contextStart,
  contextEndLine as contextEnd