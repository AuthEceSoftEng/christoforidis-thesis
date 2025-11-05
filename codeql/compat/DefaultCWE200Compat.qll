private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.FileAccessToHttpQuery::FileAccessToHttpConfig as FACTH

module DefaultCWE200Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        FACTH::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        FACTH::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        FACTH::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        FACTH::isBarrier(node)
    }
}