private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.StackTraceExposureQuery::StackTraceExposureConfig as STEC

module DefaultCWE209Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        STEC::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        STEC::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        STEC::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        STEC::isBarrier(node)
    }
}