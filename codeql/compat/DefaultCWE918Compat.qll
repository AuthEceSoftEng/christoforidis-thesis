private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.ClientSideRequestForgeryQuery::ClientSideRequestForgeryConfig as CSRFQ
import semmle.javascript.security.dataflow.RequestForgeryQuery::RequestForgeryConfig as RFQ

module DefaultCWE918Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        CSRFQ::isSource(source)
        or RFQ::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        CSRFQ::isSink(sink)
        or RFQ::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        CSRFQ::isAdditionalFlowStep(pred, succ)
        or RFQ::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        CSRFQ::isBarrier(node)
        or RFQ::isBarrier(node)
    }
}