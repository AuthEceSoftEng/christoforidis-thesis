private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.CorsMisconfigurationForCredentialsQuery::CorsMisconfigurationConfig as CMFC

module DefaultCWE346Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        CMFC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        CMFC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        CMFC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        CMFC::isBarrier(node)
    }
}