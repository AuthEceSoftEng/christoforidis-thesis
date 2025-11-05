private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.InsufficientPasswordHashQuery::InsufficientPasswordHashConfig as IPHC

module DefaultCWE916Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        IPHC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        IPHC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        IPHC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        IPHC::isBarrier(node)
    }
}