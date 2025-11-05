private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.LoopBoundInjectionQuery::LoopBoundInjectionConfig as LBIC

module DefaultCWE834Compat {
    predicate defaultIsSource(DataFlow::Node source) {
    exists(LBIC::FlowState st | LBIC::isSource(source, st))
  }
    predicate defaultIsSink(DataFlow::Node sink) {
        exists(LBIC::FlowState st | LBIC::isSink(sink, st))
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
      exists(LBIC::FlowState s1, LBIC::FlowState s2 |
      LBIC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
  }

  predicate defaultBarrier(DataFlow::Node node) {
    LBIC::isBarrier(node) or
    exists(LBIC::FlowState st | LBIC::isBarrier(node, st))
  }

}