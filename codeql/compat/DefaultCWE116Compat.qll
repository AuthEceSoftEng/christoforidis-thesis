private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.IncompleteHtmlAttributeSanitizationQuery::IncompleteHtmlAttributeSanitizationConfig as IHASC

module DefaultCWE116Compat {
    predicate defaultIsSource(DataFlow::Node source) {
    exists(IHASC::FlowState st | IHASC::isSource(source, st))
  }

    predicate defaultIsSink(DataFlow::Node sink) {
        exists(IHASC::FlowState st | IHASC::isSink(sink, st))
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(IHASC::FlowState s1, IHASC::FlowState s2 |
      IHASC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
  }

  predicate defaultBarrier(DataFlow::Node node) {
    IHASC::isBarrier(node) or
    exists(IHASC::FlowState st | IHASC::isBarrier(node, st))
  }
}