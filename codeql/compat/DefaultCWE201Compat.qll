private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.PostMessageStarQuery::PostMessageStarConfig as PMSC

module DefaultCWE201Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        PMSC::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        PMSC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        PMSC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        PMSC::isBarrier(node)
    }
}