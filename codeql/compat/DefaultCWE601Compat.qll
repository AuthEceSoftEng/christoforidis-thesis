private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.ClientSideUrlRedirectQuery::ClientSideUrlRedirectConfig as CSURC
import semmle.javascript.security.dataflow.ServerSideUrlRedirectQuery::ServerSideUrlRedirectConfig as SSURC

module DefaultCWE601Compat {
    predicate defaultIsSource(DataFlow::Node source) {
    exists(CSURC::FlowState st | CSURC::isSource(source, st))
    or SSURC::isSource(source)
  }
    predicate defaultIsSink(DataFlow::Node sink) {
        exists(CSURC::FlowState st | CSURC::isSink(sink, st))
    or SSURC::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(CSURC::FlowState s1, CSURC::FlowState s2 |
      CSURC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    or SSURC::isAdditionalFlowStep(pred, succ)
  }

  predicate defaultBarrier(DataFlow::Node node) {
    CSURC::isBarrier(node) or
    exists(CSURC::FlowState st | CSURC::isBarrier(node, st))
    or SSURC::isBarrier(node)
  }
}