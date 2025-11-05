private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.UnvalidatedDynamicMethodCallQuery::UnvalidatedDynamicMethodCallConfig as UDMCC

module DefaultCWE754Compat {
    predicate defaultIsSource(DataFlow::Node source) {
    exists(UDMCC::FlowState st | UDMCC::isSource(source, st))
  }

    predicate defaultIsSink(DataFlow::Node sink) {
        exists(UDMCC::FlowState st | UDMCC::isSink(sink, st))
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(UDMCC::FlowState s1, UDMCC::FlowState s2 |
      UDMCC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
  }

  predicate defaultBarrier(DataFlow::Node node) {
    UDMCC::isBarrier(node) or
    exists(UDMCC::FlowState st | UDMCC::isBarrier(node, st))
  }
}