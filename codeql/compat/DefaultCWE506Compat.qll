private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.HardcodedDataInterpretedAsCodeQuery::HardcodedDataInterpretedAsCodeConfig as HDIAC

module DefaultCWE506Compat {
    predicate defaultIsSource(DataFlow::Node source) {
    exists(HDIAC::FlowState st | HDIAC::isSource(source, st))
  }

  predicate defaultIsSink(DataFlow::Node sink) {
    exists(HDIAC::FlowState st | HDIAC::isSink(sink, st))
  }

  predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(HDIAC::FlowState s1, HDIAC::FlowState s2 |
      HDIAC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
  }

  predicate defaultBarrier(DataFlow::Node node) {
    HDIAC::isBarrier(node)
  }
}