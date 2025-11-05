private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.DeepObjectResourceExhaustionQuery::DeepObjectResourceExhaustionConfig as DOREC
import semmle.javascript.security.dataflow.RemotePropertyInjectionQuery::RemotePropertyInjectionConfig as RPI

module DefaultCWE400Compat {
    predicate defaultIsSource(DataFlow::Node source) {
    exists(DOREC::FlowState st | DOREC::isSource(source, st))
    or RPI::isSource(source)
  }
    predicate defaultIsSink(DataFlow::Node sink) {
        exists(DOREC::FlowState st | DOREC::isSink(sink, st))
        or RPI::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DOREC::FlowState s1, DOREC::FlowState s2 |
      DOREC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    or RPI::isAdditionalFlowStep(pred, succ)
  }

  predicate defaultBarrier(DataFlow::Node node) {
    DOREC::isBarrier(node) or
    exists(DOREC::FlowState st | DOREC::isBarrier(node, st))
    or RPI::isBarrier(node)
  }
}