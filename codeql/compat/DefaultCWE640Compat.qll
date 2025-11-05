private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.HostHeaderPoisoningInEmailGenerationQuery::HostHeaderPoisoningConfig as HHPC

module DefaultCWE640Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        HHPC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        HHPC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        HHPC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        HHPC::isBarrier(node)
    }
}