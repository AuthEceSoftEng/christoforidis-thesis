private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.HttpToFileAccessQuery::HttpToFileAccessConfig as HTFAC

module DefaultCWE912Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        HTFAC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        HTFAC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        HTFAC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        HTFAC::isBarrier(node)
    }
}