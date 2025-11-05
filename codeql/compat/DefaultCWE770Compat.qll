private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.ResourceExhaustionQuery::ResourceExhaustionConfig as REC

module DefaultCWE770Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        REC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        REC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        REC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        REC::isBarrier(node)
    }
}