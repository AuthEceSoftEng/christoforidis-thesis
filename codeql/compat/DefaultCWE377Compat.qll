private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.InsecureTemporaryFileQuery::InsecureTemporaryFileConfig as ITFC

module DefaultCWE377Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        ITFC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        ITFC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        ITFC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        ITFC::isBarrier(node)
    }
}